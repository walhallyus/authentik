"""Kerberos sync"""
from typing import Any

from django.core.exceptions import FieldError
from django.db import IntegrityError, transaction
from structlog.stdlib import get_logger

from authentik.core.exceptions import PropertyMappingExpressionException
from authentik.core.models import USER_PATH_SERVICE_ACCOUNT, User, UserTypes
from authentik.events.models import Event, EventAction
from authentik.lib.merge import MERGE_LIST_UNIQUE
from authentik.sources.kerberos.models import (
    KerberosPropertyMapping,
    KerberosSource,
    Krb5ConfContext,
    UserKerberosSourceConnection,
)


class KerberosSync:
    """Create authentik users from Kerberos principals"""

    def __init__(self, source: KerberosSource):
        self.source = source
        self._logger = get_logger().bind(source=self.source)

    def _get_initial_properties(self, principal) -> dict[str, str | dict[Any, Any]]:
        localpart, _ = principal.principal.rsplit("@", 1)
        is_service_account = "/" in localpart
        properties = {
            "username": localpart,
            "type": UserTypes.INTERNAL,
            "path": self.source.get_user_path(),
        }
        if is_service_account:
            properties.update(
                {
                    "type": UserTypes.SERVICE_ACCOUNT,
                    "path": USER_PATH_SERVICE_ACCOUNT,
                }
            )
        return properties

    def _build_properties(self, principal) -> dict[str, str | dict[Any, Any]] | None:
        properties = self._get_initial_properties(principal)
        for mapping in self.source.property_mappings.all().select_subclasses():
            if not isinstance(mapping, KerberosPropertyMapping):
                continue
            try:
                properties = mapping.evaluate(
                    user=None,
                    request=None,
                    principal=principal,
                    source=self.source,
                    properties=properties,
                )
            except PropertyMappingExpressionException as exc:
                Event.new(
                    EventAction.CONFIGURATION_ERROR,
                    message=f"Failed to evaluate property mapping: '{mapping.name}'",
                    source=self.source,
                    mapping=mapping,
                )
                self._logger.warning("Mapping failed to evaluate", exc=exc, mapping=mapping)
                continue
        return properties

    def _sync_principal(self, principal):
        user_source_connection = UserKerberosSourceConnection.objects.filter(
            source=self.source, identifier__iexact=principal.principal
        ).first()

        properties = self._build_properties(principal)
        if properties.get("username", None) is None:
            self._logger.info(
                "User username was returned as None, not syncing", principal=principal.principal
            )
            return

        # User doesn't exists
        if not user_source_connection:
            try:
                with transaction.atomic():
                    user = User.objects.create(**properties)
                    if user.type == UserTypes.INTERNAL_SERVICE_ACCOUNT:
                        user.set_unusable_password()
                        user.save()
                    user_source_connection = UserKerberosSourceConnection.objects.create(
                        source=self.source, user=user, identifier=principal.principal
                    )
            except (IntegrityError, FieldError, TypeError, AttributeError) as exc:
                Event.new(
                    EventAction.CONFIGURATION_ERROR,
                    message=f"Failed to create user: {str(exc)}.",
                    source=self.source,
                    principal=principal.principal,
                ).save()
            else:
                self._logger.debug("Synced user", user=user)
            return

        user = user_source_connection.user
        for key, value in properties.items():
            if key == "attributes":
                continue
            setattr(user, key, value)
        final_attributes = {}
        MERGE_LIST_UNIQUE.merge(final_attributes, user.attributes)
        MERGE_LIST_UNIQUE.merge(final_attributes, properties.get("attributes", {}))
        user.attributes = final_attributes
        user.save()
        self._logger.debug("Synced user", user=user)

    def sync(self):
        """Sync Kerberos principals to authentik users"""
        if not self.source.enabled or not self.source.sync_users:
            self._logger.debug("Source is disabled or has sync disabled. Skipping")
            return
        with Krb5ConfContext(self.source):
            for princ in self.source.connection().getprincs():
                self._sync_principal(princ)
