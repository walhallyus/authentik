"""Kerberos Source urls"""

from authentik.sources.kerberos.api.property_mapping import KerberosPropertyMappingViewSet
from authentik.sources.kerberos.api.source import KerberosSourceViewSet
from authentik.sources.kerberos.api.source_connection import UserKerberosSourceConnectionViewSet

api_urlpatterns = [
    ("propertymappings/kerberos", KerberosPropertyMappingViewSet),
    ("sources/user_connections/kerberos", UserKerberosSourceConnectionViewSet),
    ("sources/kerberos", KerberosSourceViewSet),
]
