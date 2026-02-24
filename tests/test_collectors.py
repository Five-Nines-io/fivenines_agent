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
        "smart_storage_health",
        "raid_storage_health",
        "processes",
        "ports",
        "temperatures",
        "fans",
        "gpu",
        "redis",
        "nginx",
        "docker",
        "qemu",
        "fail2ban",
        "caddy",
        "postgresql",
        "proxmox",
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
