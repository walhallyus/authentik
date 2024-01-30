"""Source API Views"""
from typing import Optional

from django.core.cache import cache
from drf_spectacular.utils import extend_schema
from guardian.shortcuts import get_objects_for_user
from rest_framework.decorators import action
from rest_framework.fields import BooleanField, SerializerMethodField
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from authentik.core.api.sources import SourceSerializer
from authentik.core.api.used_by import UsedByMixin
from authentik.core.api.utils import PassiveSerializer
from authentik.events.api.tasks import SystemTaskSerializer
from authentik.sources.kerberos.models import KerberosSource
from authentik.sources.kerberos.tasks import CACHE_KEY_STATUS


class KerberosSourceSerializer(SourceSerializer):
    """Kerberos Source Serializer"""

    connectivity = SerializerMethodField()

    def get_connectivity(self, source: KerberosSource) -> Optional[dict[str, str]]:
        """Get cached source connectivity"""
        return cache.get(CACHE_KEY_STATUS + source.slug, None)

    class Meta:
        model = KerberosSource
        fields = SourceSerializer.Meta.fields + [
            "sync_users",
            "sync_users_password",
            "sync_principal",
            "sync_password",
            "sync_keytab",
            "sync_ccache",
            "connectivity",
        ]
        extra_kwargs = {"bind_password": {"write_only": True}}


class KerberosSyncStatusSerializer(PassiveSerializer):
    """Kerberos Source sync status"""

    is_running = BooleanField(read_only=True)
    tasks = SystemTaskSerializer(many=True, read_only=True)


class KerberosSourceViewSet(UsedByMixin, ModelViewSet):
    """Kerberos Source Viewset"""

    queryset = KerberosSource.objects.all()
    serializer_class = KerberosSourceSerializer
    lookup_field = "slug"
    filterset_fields = [
        "name",
        "slug",
        "enabled",
        "sync_users",
        "sync_users_password",
        "sync_principal",
    ]
    search_fields = ["name", "slug"]
    ordering = ["name"]

    @extend_schema(
        responses={
            200: KerberosSyncStatusSerializer(),
        }
    )
    @action(methods=["GET"], detail=True, pagination_class=None, filter_backends=[])
    def sync_status(self, request: Request, slug: str) -> Response:
        """Get source's sync status"""
        source: KerberosSource = self.get_object()
        tasks = list(
            get_objects_for_user(request.user, "authentik_events.view_systemtask").filter(
                name="kerberos_sync",
                uid__startswith=source.slug,
            )
        )
        status = {
            "tasks": tasks,
            "is_running": source.sync_lock.locked(),
        }
        return Response(KerberosSyncStatusSerializer(status).data)
