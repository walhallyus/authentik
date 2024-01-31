"""Kerberos sync"""
from django.core.exceptions import FieldError
from django.db import IntegrityError, transaction
from structlog.stdlib import get_logger

from authentik.core.models import USER_PATH_SERVICE_ACCOUNT, User, UserTypes
from authentik.events.models import Event, EventAction
from authentik.sources.kerberos.models import (
    KerberosSource,
    Krb5ConfContext,
    UserKerberosSourceConnection,
)

LOGGER = get_logger()


def kerberos_sync(source: KerberosSource):
    """Create authentik users from Kerberos principals"""
    if not source.enabled or not source.sync_users:
        LOGGER.debug("Source is disabled or has sync disabled. Skipping", source=source)
        return
    with Krb5ConfContext(source):
        for princ in source.connection().getprincs(f"*@{source.realm}"):
            principal, _ = princ.principal.rsplit("@", 1)
            is_service_account = False
            if "/" in principal:
                is_service_account = True
                if not source.sync_service_principals:
                    continue

            user_source_connection = UserKerberosSourceConnection.objects.filter(
                source=source, identifier__iexact=principal
            ).first()

            # User already exists
            if user_source_connection:
                continue

            try:
                with transaction.atomic():
                    # TODO: property mappings
                    kwargs = {
                        "username": principal,
                        "email": princ.principal if source.sync_guess_email else "",
                        "type": UserTypes.INTERNAL,
                    }
                    if is_service_account:
                        kwargs.update(
                            {
                                "type": UserTypes.SERVICE_ACCOUNT,
                                "path": USER_PATH_SERVICE_ACCOUNT,
                            }
                        )
                    user = User.objects.create(**kwargs)
                    if is_service_account:
                        user.set_unusable_password()
                        user.save()
                    user_source_connection = UserKerberosSourceConnection.objects.create(
                        source=source, user=user, identifier=princ.principal.lower()
                    )
            except (IntegrityError, FieldError, TypeError, AttributeError) as exc:
                Event.new(
                    EventAction.CONFIGURATION_ERROR,
                    message=f"Failed to create user: {str(exc)}.",
                    source=source,
                    principal=princ.principal,
                ).save()
            else:
                LOGGER.debug("Synced user", source=source, user=user)
