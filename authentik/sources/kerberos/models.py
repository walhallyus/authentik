"""authentik Kerberos Source Models"""
import os
from pathlib import Path
from tempfile import gettempdir
from typing import Any

import kadmin
from django.core.cache import cache
from django.db import connection, models
from django.db.models.fields import b64decode
from django.utils.translation import gettext_lazy as _
from redis.lock import Lock
from rest_framework.serializers import Serializer
from structlog.stdlib import get_logger

from authentik.core.models import PropertyMapping, Source, UserSourceConnection
from authentik.lib.config import CONFIG

LOGGER = get_logger()


class KerberosSource(Source):
    """Federate Kerberos realm with authentik"""

    # python-kadmin leaks file descriptors. As such, this class attribute is used to re-use
    # existing kadmin connections instead of creating new ones, which results in less to no file
    # descriptors leaks
    _kadmin_connections: dict[str, Any] = {}

    realm = models.TextField(help_text=_("Kerberos realm"), unique=True)
    krb5_conf = models.TextField(
        blank=True,
        help_text=_("Custom krb5.conf to use. Uses the system one by default"),
    )

    password_login_enabled = models.BooleanField(
        default=False, help_text=_("Enable the passwword authentication backend"), db_index=True
    )
    password_login_update_internal_password = models.BooleanField(
        default=False,
        help_text=_(
            (
                "If enabled, the authentik-stored password will be updated upon "
                "login with the Kerberos password backend"
            )
        ),
    )

    sync_users = models.BooleanField(
        default=True, help_text=_("Sync users from Kerberos into authentik"), db_index=True
    )
    sync_users_password = models.BooleanField(
        default=True,
        help_text=_("When a user changes their password, sync it back to Kerberos"),
        db_index=True,
    )
    sync_principal = models.TextField(
        help_text=_("Principal to authenticate to kadmin for sync."), blank=True
    )
    sync_password = models.TextField(
        help_text=_("Password to authenticate to kadmin for sync"), blank=True
    )
    sync_keytab = models.TextField(
        help_text=_(
            (
                "Keytab to authenticate to kadmin for sync. "
                "Must be base64-encoded or in the form TYPE:residual"
            )
        ),
        blank=True,
    )
    sync_ccache = models.TextField(
        help_text=_(
            (
                "Credentials cache to authenticate to kadmin for sync. "
                "Must be in the form TYPE:residual"
            )
        ),
        blank=True,
    )

    @property
    def component(self) -> str:
        return "ak-source-kerberos-form"

    @property
    def serializer(self) -> type[Serializer]:
        from authentik.sources.kerberos.api.source import KerberosSourceSerializer

        return KerberosSourceSerializer

    @property
    def tempdir(self) -> Path:
        """Get temporary storage for Kerberos files"""
        path = Path(gettempdir()) / "authentik" / "sources" / "kerberos" / str(self.pk)
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        return path

    @property
    def krb5_conf_path(self) -> str | None:
        """Get krb5.conf path"""
        if not self.krb5_conf:
            return None
        conf_path = self.tempdir / "krb5.conf"
        conf_path.write_text(self.krb5_conf)
        return str(conf_path)

    def _kadmin_init(self) -> "kadmin.KAdmin | None":
        # kadmin doesn't use a ccache for its connection
        # as such, we don't need to create a separate ccache for each source
        if not self.sync_principal:
            return None
        if self.sync_password:
            return kadmin.init_with_password(
                self.sync_principal,
                self.sync_password,
                {},
                self.realm,
            )
        if self.sync_keytab:
            keytab = self.sync_keytab
            if ":" not in keytab:
                keytab_path = self.tempdir / "keytab"
                keytab_path.touch(mode=0o600)
                keytab_path.write_bytes(b64decode(self.keytab))
                keytab = f"FILE:{keytab_path}"
            return kadmin.init_with_keytab(
                self.sync_principal,
                keytab,
                {},
                self.realm,
            )
        if self.sync_ccache:
            return kadmin.init_with_ccache(
                self.sync_principal,
                self.sync_ccache,
                {},
                self.realm,
            )
        return None

    def connection(self) -> "kadmin.KAdmin | None":
        """Get kadmin connection"""
        if str(self.pk) not in self._kadmin_connections:
            kadm = self._kadmin_init()
            if kadm is not None:
                self._kadmin_connections[str(self.pk)] = self._kadmin_init()
        return self._kadmin_connections.get(str(self.pk), None)

    @property
    def sync_lock(self) -> Lock:
        """Redis lock for syncing Kerberos to prevent multiple parallel syncs happening"""
        return Lock(
            cache.client.get_client(),
            name=f"goauthentik.io/sources/kerberos/sync/{connection.schema_name}-{self.slug}",
            # Convert task timeout hours to seconds, and multiply times 3
            # (see authentik/sources/kerberos/tasks.py:54)
            # multiply by 3 to add even more leeway
            timeout=(60 * 60 * CONFIG.get_int("kerberos.task_timeout_hours")) * 3,
        )

    def check_connection(self) -> dict[str, str]:
        """Check Kerberos Connection"""
        status = {"status": "ok"}
        if not self.sync_users:
            return status
        with Krb5ConfContext(self):
            try:
                kadm = self.connection()
                if kadm is None:
                    status["status"] = "no connection"
                    return status
                status["principal_exists"] = kadm.principal_exists(self.sync_principal)
            except kadmin.Error as exc:
                status["status"] = str(exc)
        return status

    class Meta:
        verbose_name = _("Kerberos Source")
        verbose_name_plural = _("Kerberos Sources")


class Krb5ConfContext:
    """
    Context manager to set the path to the krb5.conf config file.
    """

    def __init__(self, source: KerberosSource):
        self._source = source
        self._path = self._source.krb5_conf_path
        self._previous = None

    def __enter__(self):
        if not self._path:
            return
        self._previous = os.environ.get("KRB5_CONFIG", None)
        os.environ["KRB5_CONFIG"] = self._path

    def __exit__(self, *args, **kwargs):
        if not self._path:
            return
        if self._previous:
            os.environ["KRB5_CONFIG"] = self._previous
        else:
            del os.environ["KRB5_CONFIG"]


class UserKerberosSourceConnection(UserSourceConnection):
    """Connection to configured Kerberos Sources."""

    identifier = models.TextField(db_index=True)

    @property
    def serializer(self) -> Serializer:
        from authentik.sources.kerberos.api.source_connection import (
            UserKerberosSourceConnectionSerializer,
        )

        return UserKerberosSourceConnectionSerializer

    class Meta:
        verbose_name = _("User Kerberos Source Connection")
        verbose_name_plural = _("User Kerberos Source Connections")


class KerberosPropertyMapping(PropertyMapping):
    """Map Kerberos Property to User object attribute"""

    @property
    def component(self) -> str:
        return "ak-property-mapping-kerberos-form"

    @property
    def serializer(self) -> type[Serializer]:
        from authentik.source.kerberos.api.property_mapping import KerberosPropertyMappingSerializer

        return KerberosPropertyMappingSerializer

    def __str__(self):
        return str(self.name)

    class Meta:
        verbose_name = _("Kerberos Property Mapping")
        verbose_name_plural = _("Kerberos Property Mapping")
