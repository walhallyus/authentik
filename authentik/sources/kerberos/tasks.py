"""Kerberos tasks"""
from django.core.cache import cache
from redis.exceptions import LockError
from structlog.stdlib import get_logger

from authentik.events.models import SystemTask as DBSystemTask
from authentik.lib.config import CONFIG
from authentik.root.celery import CELERY_APP
from authentik.sources.kerberos.models import KerberosSource
from authentik.sources.kerberos.sync import kerberos_sync

LOGGER = get_logger()
CACHE_KEY_STATUS = "goauthentik.io/sources/kerberos/status/"


@CELERY_APP.task()
def kerberos_sync_all():
    """Sync all sources"""
    for source in KerberosSource.objects.filter(enabled=True, sync_users=True):
        kerberos_sync_single.apply_async(args=[str(source.pk)])


@CELERY_APP.task()
def kerberos_connectivity_check(pk: str | None = None):
    """Check connectivity for Kerberos Sources"""
    # 2 hour timeout, this task should run every hour
    timeout = 60 * 60 * 2
    sources = KerberosSource.objects.filter(enabled=True, sync_users=True)
    if pk:
        sources = sources.filter(pk=pk)
    for source in sources:
        status = source.check_connection()
        cache.set(CACHE_KEY_STATUS + source.slug, status, timeout=timeout)


@CELERY_APP.task(
    # We take the configured hours timeout time by 2.5 as we run user and
    # group in parallel and then membership, so 2x is to cover the serial tasks,
    # and 0.5x on top of that to give some more leeway
    soft_time_limit=(60 * 60 * CONFIG.get_int("kerberos.task_timeout_hours")) * 2.5,
    task_time_limit=(60 * 60 * CONFIG.get_int("kerberos.task_timeout_hours")) * 2.5,
)
def kerberos_sync_single(source_pk: str):
    """Sync a single source"""
    source: KerberosSource = KerberosSource.objects.filter(pk=source_pk).first()
    if not source:
        return
    lock = source.sync_lock
    if lock.locked():
        LOGGER.debug("Kerberos sync locked, skipping task", source=source)
        return
    try:
        with lock:
            # Delete all sync tasks from the cache
            DBSystemTask.objects.filter(name="kerberos_sync", uid__startswith=source.slug).delete()
            kerberos_sync(source)
    except LockError:
        # This should never happen, we check if the lock is locked above so this
        # would only happen if there was some other timeout
        LOGGER.debug("Failed to acquire lock for Kerberos sync", source=source.slug)
