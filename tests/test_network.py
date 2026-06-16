"""Tests for network.py - cross-OS interface enumeration."""

from types import SimpleNamespace
from unittest.mock import mock_open, patch

from fivenines_agent.network import _is_loopback, interfaces, network


def _ifstats(isup):
    return SimpleNamespace(isup=isup)


# --- _is_loopback ---


def test_is_loopback_matches_lo():
    assert _is_loopback("lo") is True


def test_is_loopback_matches_windows_naming():
    assert _is_loopback("Loopback Pseudo-Interface 1") is True
    assert _is_loopback("loopback") is True


def test_is_loopback_rejects_real_interfaces():
    assert _is_loopback("eth0") is False
    assert _is_loopback("Ethernet") is False
    assert _is_loopback("wlan0") is False


# --- interfaces() OS branches ---


def test_interfaces_linux_filters_down_loopback_and_no_address():
    stats = {
        "eth0": _ifstats(True),
        "eth1": _ifstats(False),    # down
        "lo": _ifstats(True),        # loopback
        "ghost": _ifstats(True),     # no addresses
    }
    addrs = {"eth0": [object()], "ghost": []}
    with patch("fivenines_agent.network.os_family", return_value="linux"), \
         patch("fivenines_agent.network.psutil.net_if_stats", return_value=stats), \
         patch("fivenines_agent.network.psutil.net_if_addrs", return_value=addrs):
        assert interfaces() == ["eth0"]


def test_interfaces_windows_uses_psutil_path_with_windows_loopback_name():
    stats = {
        "Ethernet": _ifstats(True),
        "Wi-Fi": _ifstats(True),
        "Loopback Pseudo-Interface 1": _ifstats(True),
    }
    addrs = {"Ethernet": [object()], "Wi-Fi": [object()],
             "Loopback Pseudo-Interface 1": [object()]}
    with patch("fivenines_agent.network.os_family", return_value="windows"), \
         patch("fivenines_agent.network.psutil.net_if_stats", return_value=stats), \
         patch("fivenines_agent.network.psutil.net_if_addrs", return_value=addrs):
        result = interfaces()
    assert set(result) == {"Ethernet", "Wi-Fi"}


def test_interfaces_darwin_uses_scutil():
    fake_popen = mock_open(read_data="en0\nen1\n")
    with patch("fivenines_agent.network.os_family", return_value="darwin"), \
         patch("fivenines_agent.network.os.popen", fake_popen):
        assert interfaces() == ["en0", "en1"]


def test_interfaces_unknown_os_returns_empty():
    with patch("fivenines_agent.network.os_family", return_value="freebsd"):
        assert interfaces() == []


def test_interfaces_skips_when_net_if_addrs_raises():
    """A net_if_addrs lookup that raises continues to the next interface."""
    stats = {"eth0": _ifstats(True), "broken": _ifstats(True)}

    def fake_addrs():
        # The implementation calls .get(name, []) on the dict, so we wrap
        # in a class whose .get raises for 'broken'.
        class _D(dict):
            def get(self, k, default=None):
                if k == "broken":
                    raise OSError("nope")
                return super().get(k, default)
        return _D({"eth0": [object()]})

    with patch("fivenines_agent.network.os_family", return_value="linux"), \
         patch("fivenines_agent.network.psutil.net_if_stats", return_value=stats), \
         patch("fivenines_agent.network.psutil.net_if_addrs", side_effect=fake_addrs):
        assert interfaces() == ["eth0"]


# --- network() ---


def test_network_returns_only_known_interfaces():
    counters = {
        "eth0": SimpleNamespace(_asdict=lambda: {"bytes_sent": 1, "bytes_recv": 2}),
        "lo": SimpleNamespace(_asdict=lambda: {"bytes_sent": 0, "bytes_recv": 0}),
    }
    with patch("fivenines_agent.network.interfaces", return_value=["eth0"]), \
         patch("fivenines_agent.network.psutil.net_io_counters", return_value=counters):
        result = network()
    assert result == [{"eth0": {"bytes_sent": 1, "bytes_recv": 2}}]
