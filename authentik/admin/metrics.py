"""Metrics"""
from contextlib import contextmanager
from enum import Enum
from timeit import default_timer

from django.core.cache import cache
from django_redis.client import DefaultClient
from redis import Redis
from redis.exceptions import ResponseError
from structlog.stdlib import BoundLogger, get_logger


class Timeseries(Enum):
    """An enum of all timeseries"""

    policies_execution_count = "authentik_policies_execution_count"
    policies_execution_timing = "authentik_policies_execution_timing"
    flows_execution_count = "authentik_flows_execution_count"
    flows_stages_execution_count = "authentik_flows_stages_execution_count"
    flows_stages_execution_timing = "authentik_flows_stages_execution_timing"
    users_login_count = "authentik_users_login_count"


class MetricsManager:
    """RedisTSDB metrics"""

    supported = False
    logger: BoundLogger
    retention: int

    def __init__(self) -> None:
        self.supported = self.redis_tsdb_supported()
        self.logger = get_logger()
        # 1 week in ms
        self.retention = 7 * 24 * 60 * 60 * 1000

    def redis_tsdb_supported(self):
        """Check if redis has the timeseries module loaded"""
        modules = self.get_client().module_list()
        supported = any(module[b"name"] == b"timeseries" for module in modules)
        return supported

    def get_client(self) -> Redis:
        cache_client: DefaultClient = cache.client
        return cache_client.get_client()

    def make_key(self, ts: Timeseries, *key_parts) -> str:
        """Construct a unique key"""
        return "_".join([ts.value] + list(key_parts))

    @contextmanager
    def inc(self, ts: Timeseries, *key_parts, **labels):
        """Increase counter with labels"""
        if not self.supported:
            yield
            return
        client = self.get_client()
        yield
        labels["base_ts"] = ts.value
        client.ts().incrby(
            self.make_key(ts, *key_parts),
            1,
            retention_msecs=self.retention,
            labels=labels,
        )

    @contextmanager
    def observe(self, ts: Timeseries, *key_parts, **labels):
        """Observe time and save as a sample"""
        if not self.supported:
            yield
            return
        client = self.get_client()
        start = default_timer()
        yield
        duration = default_timer() - start
        labels["base_ts"] = ts.value
        client.ts().add(
            self.make_key(ts, *key_parts),
            "*",
            retention_msecs=self.retention,
            value=duration,
            labels=labels,
        )


metrics = MetricsManager()
