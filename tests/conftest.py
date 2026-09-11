"""Shared fixtures.

The agent caches a number of things at module level for per-tick performance
(package reads, the Docker client, the mysql replication-verb memo, the NVML
session, the synchronizer TLS context). Tests patch the underlying functions
per test, so any cached value leaking across tests makes them order-dependent;
this autouse fixture resets every such cache before each test.
"""

import os
from unittest.mock import MagicMock, patch

import pytest

import fivenines_agent.dns_resolver as dns_resolver_module
import fivenines_agent.docker as docker_module
import fivenines_agent.fail2ban as fail2ban_module
import fivenines_agent.gpu as gpu_module
import fivenines_agent.ip as ip_module
import fivenines_agent.mysql as mysql_module
import fivenines_agent.packages as packages_module
import fivenines_agent.qemu as qemu_module
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
    # Both pieces of process-global state QEMUCollector mutates: the log-once
    # register and the LIBVIRT_AUTOSTART it writes into the real environment.
    qemu_module._clear_refusal()  # the production reset path, not a bare assignment
    os.environ.pop("LIBVIRT_AUTOSTART", None)
    yield


@pytest.fixture
def make_fake_libvirt():
    """Factory for a libvirt module double whose openReadOnly yields a usable
    connection (zero domains, no host info). A factory rather than a plain
    fixture so a test can build one per configuration under test."""

    def _make():
        lib = MagicMock()
        conn = MagicMock()
        conn.listAllDomains.return_value = []
        conn.getInfo.return_value = None
        lib.openReadOnly.return_value = conn
        return lib

    return _make


@pytest.fixture
def fake_libvirt(make_fake_libvirt):
    """A libvirt module double installed as fivenines_agent.qemu.libvirt for
    the test."""
    lib = make_fake_libvirt()
    with patch("fivenines_agent.qemu.libvirt", lib):
        yield lib


@pytest.fixture
def quiet_qemu_log():
    """fivenines_agent.qemu.log replaced by a mock (refusals log at error
    level, which would otherwise print during the run); yields the mock."""
    with patch("fivenines_agent.qemu.log") as mock_log:
        yield mock_log
