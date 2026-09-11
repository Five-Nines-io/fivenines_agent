"""Tests for the collector registry and dispatch loop."""

import sys
from unittest.mock import MagicMock, patch

# Mock libvirt before any fivenines_agent imports that transitively need it
sys.modules.setdefault("libvirt", MagicMock())


from fivenines_agent.collectors import COLLECTORS, collect_metrics  # noqa: E402


def test_registry_has_expected_config_keys():
    """All known config keys are present in the registry."""
    config_keys = [entry[0] for entry in COLLECTORS]
    expected = [
        "cpu",
        "memory",
        "network",
        "partitions",
        "io",
        "logs",
        "smart_storage_health",
        "raid_storage_health",
        "ceph",
        "zfs",
        "processes",
        "ports",
        "temperatures",
        "fans",
        "nvidia_gpu",
        "redis",
        "memcached",
        "nginx",
        "apache",
        "php_fpm",
        "haproxy",
        "docker",
        "qemu",
        "fail2ban",
        "caddy",
        "tsdb",
        "vllm",
        "sglang",
        "postgresql",
        "mysql",
        "rabbitmq",
        "proxmox",
        "wireguard",
        "tailscale",
        "systemd",
        "disk_health",
    ]
    assert config_keys == expected


def test_collect_metrics_skips_disabled():
    """Collectors are skipped when their config key is falsy."""
    config = {"cpu": False, "memory": None, "network": 0}
    data = {}
    collect_metrics(config, data)
    assert data == {}


def test_collect_metrics_calls_simple_collector():
    """A simple (no-kwargs) collector is called when config key is truthy."""
    mock_fn = MagicMock(return_value=42)
    registry = [("metric", [("metric", mock_fn, False)])]
    config = {"metric": True}
    data = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data)

    mock_fn.assert_called_once_with()
    assert data == {"metric": 42}


def test_collect_metrics_calls_kwargs_collector():
    """A kwargs collector unpacks the config dict as keyword arguments."""
    mock_fn = MagicMock(return_value={"ok": True})
    registry = [("svc", [("svc", mock_fn, True)])]
    config = {"svc": {"host": "localhost", "port": 8080}}
    data = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data)

    mock_fn.assert_called_once_with(host="localhost", port=8080)
    assert data == {"svc": {"ok": True}}


def test_collect_metrics_kwargs_with_non_dict_config():
    """When pass_kwargs=True but config value is not a dict, call with no args."""
    mock_fn = MagicMock(return_value="result")
    registry = [("svc", [("svc", mock_fn, True)])]
    config = {"svc": True}
    data = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data)

    mock_fn.assert_called_once_with()
    assert data == {"svc": "result"}


def test_collect_metrics_multi_key():
    """A config key mapping to multiple data keys calls each collector."""
    mock_a = MagicMock(return_value="a")
    mock_b = MagicMock(return_value="b")
    registry = [("multi", [("key_a", mock_a, False), ("key_b", mock_b, False)])]
    config = {"multi": True}
    data = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data)

    mock_a.assert_called_once_with()
    mock_b.assert_called_once_with()
    assert data == {"key_a": "a", "key_b": "b"}


def test_collect_metrics_only_enabled():
    """Only collectors with truthy config are invoked."""
    mock_on = MagicMock(return_value="on")
    mock_off = MagicMock(return_value="off")
    registry = [
        ("enabled", [("enabled", mock_on, False)]),
        ("disabled", [("disabled", mock_off, False)]),
    ]
    config = {"enabled": True}
    data = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data)

    mock_on.assert_called_once()
    mock_off.assert_not_called()
    assert data == {"enabled": "on"}


def test_registry_entries_are_tuples():
    """Each registry entry has the expected structure."""
    for config_key, collectors in COLLECTORS:
        assert isinstance(config_key, str)
        assert isinstance(collectors, list)
        for data_key, fn, pass_kwargs in collectors:
            assert isinstance(data_key, str)
            assert callable(fn)
            assert isinstance(pass_kwargs, bool)


# --- Telemetry support ---


def test_collect_metrics_with_telemetry_records_timing():
    """When telemetry dict is passed, duration_ms is recorded per collector."""
    mock_fn = MagicMock(return_value=42)
    registry = [("metric", [("metric", mock_fn, False)])]
    config = {"metric": True}
    data = {}
    telemetry = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data, telemetry)

    assert data == {"metric": 42}
    assert "metric" in telemetry
    assert "duration_ms" in telemetry["metric"]
    assert isinstance(telemetry["metric"]["duration_ms"], float)
    assert "errors" not in telemetry["metric"]


def test_collect_metrics_with_telemetry_captures_error():
    """When a collector raises, telemetry records errors and data gets None."""
    mock_fn = MagicMock(side_effect=RuntimeError("fail"))
    registry = [("broken", [("broken", mock_fn, False)])]
    config = {"broken": True}
    data = {}
    telemetry = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data, telemetry)

    assert data["broken"] is None
    assert "broken" in telemetry
    assert "duration_ms" in telemetry["broken"]
    assert "errors" in telemetry["broken"]
    assert "fail" in telemetry["broken"]["errors"]


def test_collect_metrics_with_telemetry_kwargs():
    """Kwargs collector works correctly with telemetry."""
    mock_fn = MagicMock(return_value={"ok": True})
    registry = [("svc", [("svc", mock_fn, True)])]
    config = {"svc": {"host": "localhost", "port": 8080}}
    data = {}
    telemetry = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data, telemetry)

    mock_fn.assert_called_once_with(host="localhost", port=8080)
    assert data == {"svc": {"ok": True}}
    assert "svc" in telemetry
    assert "duration_ms" in telemetry["svc"]


def test_collect_metrics_without_telemetry_unchanged():
    """When telemetry is None (default), original behavior is preserved."""
    mock_fn = MagicMock(return_value=42)
    registry = [("metric", [("metric", mock_fn, False)])]
    config = {"metric": True}
    data = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data)

    mock_fn.assert_called_once_with()
    assert data == {"metric": 42}


# --- Capability gating ---


def _reset_skip_log():
    from fivenines_agent.collectors import _logged_capability_skips

    _logged_capability_skips.clear()


def test_capability_false_skips_collector():
    """When capability is False, the collector is not invoked."""
    _reset_skip_log()
    mock_fn = MagicMock(return_value="data")
    registry = [("nvidia_gpu", [("nvidia_gpu", mock_fn, False)])]
    config = {"nvidia_gpu": True}
    permissions = {"nvidia_gpu": False}
    data = {}
    telemetry = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data, telemetry, permissions)

    mock_fn.assert_not_called()
    assert data == {}
    assert "nvidia_gpu" not in telemetry


def test_capability_true_invokes_collector():
    """When capability is True, the collector runs normally."""
    _reset_skip_log()
    mock_fn = MagicMock(return_value="data")
    registry = [("nvidia_gpu", [("nvidia_gpu", mock_fn, False)])]
    config = {"nvidia_gpu": True}
    permissions = {"nvidia_gpu": True}
    data = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data, permissions=permissions)

    mock_fn.assert_called_once()
    assert data == {"nvidia_gpu": "data"}


def test_capability_missing_does_not_gate():
    """When the capability key is absent from the dict, no gating happens."""
    _reset_skip_log()
    mock_fn = MagicMock(return_value="ok")
    registry = [("redis", [("redis", mock_fn, False)])]
    config = {"redis": True}
    permissions = {"cpu": True}  # 'redis' absent
    data = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data, permissions=permissions)

    mock_fn.assert_called_once()
    assert data == {"redis": "ok"}


def test_capability_overrides_smart_storage():
    """smart_storage_health config gates on smart_storage capability."""
    _reset_skip_log()
    mock_fn = MagicMock(return_value="x")
    registry = [("smart_storage_health", [("smart_storage_health", mock_fn, False)])]
    config = {"smart_storage_health": True}
    permissions = {"smart_storage": False}
    data = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data, permissions=permissions)

    mock_fn.assert_not_called()


def test_capability_overrides_raid_storage():
    """raid_storage_health config gates on raid_storage capability."""
    _reset_skip_log()
    mock_fn = MagicMock(return_value="x")
    registry = [("raid_storage_health", [("raid_storage_health", mock_fn, False)])]
    config = {"raid_storage_health": True}
    permissions = {"raid_storage": False}
    data = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data, permissions=permissions)

    mock_fn.assert_not_called()


def test_capability_overrides_logs_journald():
    """logs config gates on the journald capability (not a 'logs' capability)."""
    _reset_skip_log()
    mock_fn = MagicMock(return_value="x")
    registry = [("logs", [("logs", mock_fn, True)])]
    config = {"logs": {"units": ["nginx.service"]}}
    permissions = {"journald": False}
    data = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data, permissions=permissions)

    mock_fn.assert_not_called()


def test_skip_logged_only_once_per_process():
    """Subsequent skipped invocations do not re-log."""
    _reset_skip_log()
    mock_fn = MagicMock(return_value="x")
    registry = [("nvidia_gpu", [("nvidia_gpu", mock_fn, False)])]
    config = {"nvidia_gpu": True}
    permissions = {"nvidia_gpu": False}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        with patch("fivenines_agent.collectors.log") as mock_log:
            collect_metrics(config, {}, permissions=permissions)
            collect_metrics(config, {}, permissions=permissions)
            collect_metrics(config, {}, permissions=permissions)

    skip_calls = [c for c in mock_log.call_args_list if "Skipping" in c.args[0]]
    assert len(skip_calls) == 1


def test_no_permissions_no_gating():
    """When permissions is None, capability gating is bypassed."""
    _reset_skip_log()
    mock_fn = MagicMock(return_value="x")
    registry = [("nvidia_gpu", [("nvidia_gpu", mock_fn, False)])]
    config = {"nvidia_gpu": True}
    data = {}

    with patch("fivenines_agent.collectors.COLLECTORS", registry):
        collect_metrics(config, data)

    mock_fn.assert_called_once()


def test_qemu_refused_uri_reaches_payload_as_null(fake_libvirt, quiet_qemu_log):
    """End to end through the real registry: a config-driven qemu URI outside
    the local-socket allowlist (agent #142) never reaches libvirt and lands in
    the payload as data["qemu"] = None -- a collection failure the server
    skips -- not [] (zero VMs, which would prune every VM row)."""
    config = {"qemu": {"uri": "qemu+ext:///system?command=/tmp/evil"}}
    data = {}

    collect_metrics(config, data, permissions={"qemu": True})

    assert "qemu" in data
    assert data["qemu"] is None
    fake_libvirt.openReadOnly.assert_not_called()


def test_qemu_config_shapes_open_the_expected_uri_through_registry(make_fake_libvirt):
    """Regression guard for the shipped configurations, end to end through the
    real registry: the plain boolean splats no kwargs and still opens the
    collector's qemu:///system default, and a dashboard-configured URI on the
    allowlist is opened verbatim. Both report [] (zero VMs) -- never None --
    so the allowlist is inert for every accepted shape."""
    for config_value, expected_uri in [
        (True, "qemu:///system"),
        ({"uri": "qemu:///session"}, "qemu:///session"),
        (
            {"uri": "qemu+unix:///system?socket=/run/libvirt/libvirt-sock"},
            "qemu+unix:///system?socket=/run/libvirt/libvirt-sock",
        ),
    ]:
        fake_libvirt = make_fake_libvirt()
        conn = fake_libvirt.openReadOnly.return_value
        data = {}

        with patch("fivenines_agent.qemu.libvirt", fake_libvirt):
            collect_metrics({"qemu": config_value}, data, permissions={"qemu": True})

        fake_libvirt.openReadOnly.assert_called_once_with(expected_uri)
        assert data["qemu"] == []
        conn.close.assert_called_once()


def test_qemu_refused_uri_is_still_capability_gated_through_registry(
    fake_libvirt, quiet_qemu_log
):
    """The allowlist sits BEHIND the capability gate, not in front of it: when
    the qemu capability is unavailable the collector is skipped entirely and
    the key stays absent, so a refused URI cannot turn a skipped collector
    into a null row."""
    _reset_skip_log()
    data = {}
    collect_metrics(
        {"qemu": {"uri": "qemu+ssh://root@host/system"}},
        data,
        permissions={"qemu": False},
    )
    assert "qemu" not in data
    fake_libvirt.openReadOnly.assert_not_called()
