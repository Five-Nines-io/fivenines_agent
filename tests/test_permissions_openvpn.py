"""Tests for the OpenVPN capability probe (_can_access_openvpn, agent #145).

The probe body lives in openvpn.py so that it cannot drift from the read it
describes (the wireguard WG_DUMP_ARGV precedent); this file pins the wiring --
the probe is registered, informational-only, hinted, and reports its reason.
Constructed via __new__ so we exercise only the probe, not the full _probe_all.
"""

from unittest.mock import patch

from fivenines_agent import permissions
from fivenines_agent.permissions import CAPABILITY_HINTS, PermissionProbe


def _probe():
    p = PermissionProbe.__new__(PermissionProbe)
    p._current_reason = None
    return p


def test_openvpn_true_when_an_instance_answers():
    with patch.object(
        permissions, "probe_management_access", return_value=(True, None)
    ):
        p = _probe()
        assert p._can_access_openvpn() is True
        assert p._current_reason is None


def test_openvpn_false_records_the_reason():
    with patch.object(
        permissions,
        "probe_management_access",
        return_value=(False, "/run/openvpn-server/a.sock: closed by the daemon"),
    ):
        p = _probe()
        assert p._can_access_openvpn() is False
        assert "closed by the daemon" in p._current_reason


def test_openvpn_probe_delegates_rather_than_reimplementing():
    """It must call the collector's own helper.

    A second, independent "can we get at this" implementation is exactly how a
    probe stops describing the read it gates -- see #144.
    """
    with patch.object(
        permissions, "probe_management_access", return_value=(True, None)
    ) as delegate:
        _probe()._can_access_openvpn()
    delegate.assert_called_once_with()


def test_openvpn_probe_never_uses_os_access():
    """Measured: the management socket is created mode 0777 (OpenVPN umask(0)s
    before bind), so os.access passes for every user on the box and would report
    the capability available on hosts where every read is refused."""
    with patch.object(
        permissions, "probe_management_access", return_value=(False, "nope")
    ), patch.object(permissions.os, "access") as access:
        _probe()._can_access_openvpn()
    access.assert_not_called()


def test_openvpn_is_registered_as_a_linux_capability():
    p = PermissionProbe.__new__(PermissionProbe)
    p._docker_socket_url = None
    specs = p._linux_probe_specs()
    assert "openvpn" in specs
    probe_callable, args = specs["openvpn"]
    assert probe_callable == p._can_access_openvpn
    assert args == ()


def test_openvpn_is_not_a_windows_capability():
    """OpenVPN on Windows exposes TCP management only, which this collector
    deliberately does not read."""
    p = PermissionProbe.__new__(PermissionProbe)
    assert "openvpn" not in p._windows_probe_specs()


def test_openvpn_hint_names_the_two_config_lines():
    hint = CAPABILITY_HINTS["openvpn"]
    assert "management" in hint
    assert "management-client-group" in hint


def test_openvpn_appears_in_the_networking_banner_group():
    groups = dict(permissions.LINUX_BANNER_GROUPS)
    assert "openvpn" in groups["Networking"]
