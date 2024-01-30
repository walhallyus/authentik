"""Kerberos sync"""
from django.core.exceptions import FieldError
from django.db import IntegrityError, transaction
from structlog.stdlib import get_logger

from authentik.core.models import User
from authentik.events.models import Event, EventAction
from authentik.sources.kerberos.models import KerberosSource, UserKerberosSourceConnection

LOGGER = get_logger()


def kerberos_sync(source: KerberosSource):
    """Create authentik users from Kerberos principals"""
    if not source.enabled or not source.sync_users:
        LOGGER.debug("Source is disabled or has sync disabled. Skipping", source=source)
        return
    for princ in source.connection().getprincs(f"*@{source.realm}"):
        principal, _ = princ.principal.rsplit("@", 1)
        # Skipping service principals
        if "/" in principal:
            continue

        user_source_connection = UserKerberosSourceConnection.objects.filter(
            source=source, identifier__iexact=principal
        ).first()

        # User already exists
        if user_source_connection:
            continue

        try:
            with transaction.atomic():
                email = princ.principal if source.sync_guess_email else ""
                user = User.objects.create(username=principal, email=email)
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
