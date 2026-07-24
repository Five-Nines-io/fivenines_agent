"""Tests for network.py - cross-OS interface enumeration + bridge enrichment."""

import json
import os
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import mock_open, patch

from fivenines_agent.network import (
    MAX_LINK_SPEED_MBPS,
    SYS_CLASS_NET,
    _bridge_members,
    _interface_type,
    _is_bridge,
    _is_loopback,
    _link_speed_bps,
    _read_sysfs_net,
    interfaces,
    network,
)


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


# --- network() backward-compat (non-Linux: no sysfs enrichment) ---


def test_network_returns_only_known_interfaces():
    """On non-Linux hosts the payload keeps its historical raw-counter shape."""
    counters = {
        "eth0": SimpleNamespace(_asdict=lambda: {"bytes_sent": 1, "bytes_recv": 2}),
        "lo": SimpleNamespace(_asdict=lambda: {"bytes_sent": 0, "bytes_recv": 0}),
    }
    with patch("fivenines_agent.network.os_family", return_value="darwin"), \
         patch("fivenines_agent.network.interfaces", return_value=["eth0"]), \
         patch("fivenines_agent.network.psutil.net_io_counters", return_value=counters):
        result = network()
    assert result == [{"eth0": {"bytes_sent": 1, "bytes_recv": 2}}]


# --- sysfs helpers ---


def test_read_sysfs_net_reads_and_strips():
    with patch("builtins.open", mock_open(read_data="10000\n")):
        assert _read_sysfs_net("eno1", "speed") == "10000"


def test_read_sysfs_net_returns_none_on_oserror():
    # A down/virtual interface raises EINVAL when `speed` is read; a missing
    # attr raises FileNotFoundError. Both are OSError -> None.
    with patch("builtins.open", side_effect=OSError("EINVAL")):
        assert _read_sysfs_net("wg0", "speed") is None


def test_read_sysfs_net_returns_none_on_valueerror():
    # open() raises ValueError on an embedded null byte; read() raises
    # UnicodeDecodeError (a ValueError subclass) on non-ASCII text. Both -> None.
    with patch("builtins.open", side_effect=ValueError("embedded null byte")):
        assert _read_sysfs_net("eno1", "speed") is None


def test_is_bridge_true_when_bridge_dir_present():
    with patch("fivenines_agent.network.os.path.isdir", return_value=True) as isdir:
        assert _is_bridge("vmbr0") is True
    isdir.assert_called_once_with(os.path.join(SYS_CLASS_NET, "vmbr0", "bridge"))


def test_is_bridge_false_when_absent():
    with patch("fivenines_agent.network.os.path.isdir", return_value=False):
        assert _is_bridge("eno1") is False


def test_bridge_members_lists_sorted():
    with patch("fivenines_agent.network.os.listdir",
               return_value=["tap100i0", "eno1"]):
        assert _bridge_members("vmbr0") == ["eno1", "tap100i0"]


def test_bridge_members_returns_empty_on_oserror():
    with patch("fivenines_agent.network.os.listdir", side_effect=OSError):
        assert _bridge_members("eno1") == []


def test_interface_type_bridge():
    with patch("fivenines_agent.network._is_bridge", return_value=True):
        assert _interface_type("vmbr0") == "bridge"


def test_interface_type_physical_when_device_present():
    with patch("fivenines_agent.network._is_bridge", return_value=False), \
         patch("fivenines_agent.network.os.path.exists", return_value=True) as exists:
        assert _interface_type("eno1") == "physical"
    exists.assert_called_once_with(os.path.join(SYS_CLASS_NET, "eno1", "device"))


def test_interface_type_virtual_when_neither():
    with patch("fivenines_agent.network._is_bridge", return_value=False), \
         patch("fivenines_agent.network.os.path.exists", return_value=False):
        assert _interface_type("wg0") == "virtual"


def test_link_speed_bps_converts_mbps_to_bps():
    with patch("fivenines_agent.network._read_sysfs_net", return_value="10000"):
        assert _link_speed_bps("eno1") == 10_000_000_000


def test_link_speed_bps_none_when_file_missing():
    with patch("fivenines_agent.network._read_sysfs_net", return_value=None):
        assert _link_speed_bps("wg0") is None


def test_link_speed_bps_none_on_non_numeric():
    with patch("fivenines_agent.network._read_sysfs_net", return_value="unknown"):
        assert _link_speed_bps("eno1") is None


def test_link_speed_bps_none_on_minus_one():
    # The kernel reports -1 for many virtual/down links: "unknown", not a speed.
    with patch("fivenines_agent.network._read_sysfs_net", return_value="-1"):
        assert _link_speed_bps("vmbr0") is None


def test_link_speed_bps_none_on_zero():
    with patch("fivenines_agent.network._read_sysfs_net", return_value="0"):
        assert _link_speed_bps("eno1") is None


def test_link_speed_bps_none_above_max():
    # A broken/out-of-tree driver can print an unsigned sentinel (2^32-1) into
    # `speed`; without an upper clamp it would become a multi-petabit rate that
    # silently zeroes the downstream saturation ratio.
    with patch("fivenines_agent.network._read_sysfs_net", return_value="4294967295"):
        assert _link_speed_bps("eno1") is None


def test_link_speed_bps_allows_boundary_max():
    # The cap itself is a real (if huge) speed and must still convert.
    with patch("fivenines_agent.network._read_sysfs_net",
               return_value=str(MAX_LINK_SPEED_MBPS)):
        assert _link_speed_bps("eno1") == MAX_LINK_SPEED_MBPS * 1_000_000


# --- network() enrichment (Linux) ---


def _ns(**counters):
    return SimpleNamespace(_asdict=lambda: dict(counters))


def test_network_enriches_bridge_physical_virtual_and_tags_members():
    """Linux payload gains interface_type, link speed, member count + bridge tag.

    vmbr0 is a bridge with two members (one of which, eno1, is itself addressed
    and so appears in its own right and gets tagged); eno2 is a plain physical
    NIC; wg0 is virtual with no link speed.
    """
    ifaces = ["vmbr0", "eno1", "eno2", "wg0"]
    counters = {
        "vmbr0": _ns(bytes_sent=1, bytes_recv=2),
        "eno1": _ns(bytes_sent=3, bytes_recv=4),
        "eno2": _ns(bytes_sent=5, bytes_recv=6),
        "wg0": _ns(bytes_sent=7, bytes_recv=8),
        "docker0": _ns(bytes_sent=9, bytes_recv=9),  # not in ifaces -> skipped
    }
    bridges = {"vmbr0": ["eno1", "tap100i0"]}
    devices = {"eno1", "eno2"}
    speeds = {"vmbr0": "-1", "eno1": "10000", "eno2": "1000", "wg0": None}

    def fake_isdir(path):
        iface, rest = _split(path)
        return rest == "bridge" and iface in bridges

    def fake_exists(path):
        iface, rest = _split(path)
        return rest == "device" and iface in devices

    def fake_listdir(path):
        iface, rest = _split(path)
        if rest == "brif" and iface in bridges:
            return list(bridges[iface])
        raise OSError

    def fake_read(iface, attr):
        return speeds.get(iface)

    with ExitStack() as stack:
        stack.enter_context(
            patch("fivenines_agent.network.os_family", return_value="linux"))
        stack.enter_context(
            patch("fivenines_agent.network.interfaces", return_value=ifaces))
        stack.enter_context(
            patch("fivenines_agent.network.psutil.net_io_counters",
                  return_value=counters))
        stack.enter_context(
            patch("fivenines_agent.network.os.path.isdir", side_effect=fake_isdir))
        stack.enter_context(
            patch("fivenines_agent.network.os.path.exists", side_effect=fake_exists))
        stack.enter_context(
            patch("fivenines_agent.network.os.listdir", side_effect=fake_listdir))
        stack.enter_context(
            patch("fivenines_agent.network._read_sysfs_net", side_effect=fake_read))
        result = network()

    by_name = {list(e)[0]: list(e.values())[0] for e in result}
    assert set(by_name) == {"vmbr0", "eno1", "eno2", "wg0"}

    assert by_name["vmbr0"] == {
        "bytes_sent": 1, "bytes_recv": 2,
        "interface_type": "bridge",
        "network_link_speed_bps": None,
        "bridge_member_count": 2,
    }
    assert by_name["eno1"] == {
        "bytes_sent": 3, "bytes_recv": 4,
        "interface_type": "physical",
        "network_link_speed_bps": 10_000_000_000,
        "bridge": "vmbr0",
    }
    # Plain physical NIC: no bridge_member_count, no bridge tag.
    assert by_name["eno2"] == {
        "bytes_sent": 5, "bytes_recv": 6,
        "interface_type": "physical",
        "network_link_speed_bps": 1_000_000_000,
    }
    assert by_name["wg0"] == {
        "bytes_sent": 7, "bytes_recv": 8,
        "interface_type": "virtual",
        "network_link_speed_bps": None,
    }


def _split(path):
    """Split /sys/class/net/<iface>/<rest...> into (iface, rest).

    network() builds these paths with os.path.join, which uses the host's
    separator. On the Windows CI runner (where the tests force the linux branch)
    that is '\\', so normalise to '/' before splitting -- otherwise the mock
    would model sysfs differently per platform and the enrichment would silently
    misparse.
    """
    rel = path[len(SYS_CLASS_NET):].replace("\\", "/").strip("/")
    parts = rel.split("/", 1)
    return parts[0], (parts[1] if len(parts) > 1 else "")


# --- cross-repo contract (fivenines-server, issue #50) --------------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "network_contract_payload.json"
)

# The per-interface keys the server ingester reads to compute saturation. A
# rename or drop must fail loudly here, not silently break the calc downstream.
_BASE_KEYS = {
    "bytes_sent", "bytes_recv", "packets_sent", "packets_recv",
    "errin", "errout", "dropin", "dropout",
    "interface_type", "network_link_speed_bps",
}


def test_contract_fixture_round_trip():
    """SHARED FIXTURE (cross-repo contract): fixtures/network_contract_payload.json.

    Asserted on both sides:
    - here: with os_family forced to 'linux', interfaces()/net_io_counters
      mocked from the fixture and /sys/class/net modelled by fixture['sysfs'],
      network() must equal fixture['payload']['network'];
    - fivenines-server: its collect spec posts payload['network'] under
      data['network'] and asserts the ingester consumes interface_type /
      network_link_speed_bps / bridge_member_count / bridge.

    Change the payload shape only in lockstep with the server spec and its
    byte-identical fixture copy.
    """
    with open(_FIXTURE_PATH) as f:
        fixture = json.load(f)

    model = fixture["sysfs"]
    counters = {
        name: _ns(**vals) for name, vals in fixture["counters"].items()
    }

    def fake_isdir(path):
        iface, rest = _split(path)
        return rest == "bridge" and model.get(iface, {}).get("bridge", False)

    def fake_exists(path):
        iface, rest = _split(path)
        return rest == "device" and model.get(iface, {}).get("device", False)

    def fake_listdir(path):
        iface, rest = _split(path)
        if rest == "brif":
            return list(model.get(iface, {}).get("members", []))
        raise OSError

    def fake_read(iface, attr):
        if attr == "speed":
            return model.get(iface, {}).get("speed")
        return None

    with ExitStack() as stack:
        stack.enter_context(
            patch("fivenines_agent.network.os_family", return_value="linux"))
        stack.enter_context(
            patch("fivenines_agent.network.interfaces",
                  return_value=fixture["interfaces"]))
        stack.enter_context(
            patch("fivenines_agent.network.psutil.net_io_counters",
                  return_value=counters))
        stack.enter_context(
            patch("fivenines_agent.network.os.path.isdir", side_effect=fake_isdir))
        stack.enter_context(
            patch("fivenines_agent.network.os.path.exists", side_effect=fake_exists))
        stack.enter_context(
            patch("fivenines_agent.network.os.listdir", side_effect=fake_listdir))
        stack.enter_context(
            patch("fivenines_agent.network._read_sysfs_net", side_effect=fake_read))
        out = network()

    assert out == fixture["payload"]["network"]

    # Structural pins: every entry carries the base keys; bridge-only and
    # member-only keys appear exactly where the contract says.
    by_name = {list(e)[0]: list(e.values())[0] for e in out}
    for iface, values in by_name.items():
        assert _BASE_KEYS <= set(values), iface
    assert by_name["vmbr0"]["bridge_member_count"] == 2
    assert "bridge_member_count" not in by_name["eno2"]
    assert by_name["eno1"]["bridge"] == "vmbr0"
    assert "bridge" not in by_name["eno2"]


def test_fixture_agent_min_version():
    with open(_FIXTURE_PATH) as f:
        fixture = json.load(f)
    assert fixture["agent_min_version"] == "1.11.6"
