"""Shared fixtures.

The agent caches a number of things at module level for per-tick performance
(package reads, the Docker client, the mysql replication-verb memo, the NVML
session, the synchronizer TLS context). Tests patch the underlying functions
per test, so any cached value leaking across tests makes them order-dependent;
this autouse fixture resets every such cache before each test.
"""

import pytest

import fivenines_agent.dns_resolver as dns_resolver_module
import fivenines_agent.docker as docker_module
import fivenines_agent.fail2ban as fail2ban_module
import fivenines_agent.gpu as gpu_module
import fivenines_agent.ip as ip_module
import fivenines_agent.mysql as mysql_module
import fivenines_agent.packages as packages_module
import fivenines_agent.raid_storage as raid_module
import fivenines_agent.synchronizer as synchronizer_module
from fivenines_agent.cache import TTLCache


@pytest.fixture(autouse=True)
def _reset_process_caches():
    packages_module._packages_cache = TTLCache()
    mysql_module._replica_status_sql = mysql_module.REPLICA_STATUS_SQL
    raid_module._mdadm_version = None
    fail2ban_module._version_cache = None
    gpu_module._nvml_ready = False
    synchronizer_module._ssl_context = None
    ip_module._ssl_context = None
    dns_resolver_module._resolver = None
    docker_module.invalidate_docker_client()
    yield
