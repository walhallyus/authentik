"""Kerberos Source Auth tests"""
from authentik.core.models import User
from authentik.lib.generators import generate_id, generate_key
from authentik.sources.kerberos.auth import KerberosBackend
from authentik.sources.kerberos.models import KerberosSource, UserKerberosSourceConnection
from authentik.sources.kerberos.tests.utils import KerberosTest

LDAP_PASSWORD = generate_key()


class KerberosAuthTests(KerberosTest):
    """Kerberos Auth tests"""

    def setUp(self):
        self.source = KerberosSource.objects.create(
            name="kerberos",
            slug="kerberos",
            realm=self.realm.realm,
            password_login_enabled=True,
            sync_users=False,
        )
        self.user = User.objects.create(username=generate_id())
        UserKerberosSourceConnection.objects.create(
            source=self.source, user=self.user, identifier=self.realm.user_princ
        )

    def test_auth_username(self):
        """Test auth username"""
        backend = KerberosBackend()
        self.assertEqual(
            backend.authenticate(
                None, username=self.user.username, password=self.realm.password("user")
            ),
            self.user,
        )

    def test_auth_principal(self):
        """Test auth principal"""
        backend = KerberosBackend()
        self.assertEqual(
            backend.authenticate(
                None, username=self.realm.user_princ, password=self.realm.password("user")
            ),
            self.user,
        )
