"""Tests for the ports.py psutil rewrite.

The Linux-output contract is pinned here: changes to listening_ports() must
preserve (port, proto_name, address) tuples, the dual-stack annotation, and
the ephemeral-port filtering. This is the D8 REGRESSION test - mandatory.
"""

import builtins
import socket
from types import SimpleNamespace
from unittest.mock import mock_open, patch

import psutil

from fivenines_agent.ports import (
    PROTOCOLS,
    check_ipv6_dual_stack,
    get_ephemeral_port_range,
    listening_ports,
)


def _conn(family, type_, ip, port, status):
    """Build a fake psutil sconn for tests."""
    return SimpleNamespace(
        fd=-1,
        family=family,
        type=type_,
        laddr=SimpleNamespace(ip=ip, port=port),
        raddr=(),
        status=status,
        pid=None,
    )


def _tcp4(ip, port, status=psutil.CONN_LISTEN):
    return _conn(socket.AF_INET, socket.SOCK_STREAM, ip, port, status)


def _tcp6(ip, port, status=psutil.CONN_LISTEN):
    return _conn(socket.AF_INET6, socket.SOCK_STREAM, ip, port, status)


def _udp4(ip, port, status=psutil.CONN_NONE):
    return _conn(socket.AF_INET, socket.SOCK_DGRAM, ip, port, status)


def _udp6(ip, port, status=psutil.CONN_NONE):
    return _conn(socket.AF_INET6, socket.SOCK_DGRAM, ip, port, status)


def test_listening_ports_udp6_unconn_included():
    """UDP6 listening sockets (CONN_NONE on IPv6) come back as UDP (IPv6)."""
    with patch("fivenines_agent.ports.psutil.net_connections",
               return_value=[_udp6("::", 5353)]):
        result = listening_ports()
    assert (5353, "UDP (IPv6)", "::") in result


# --- listening_ports output contract ---


def test_listening_ports_returns_list_of_tuples():
    with patch("fivenines_agent.ports.psutil.net_connections", return_value=[]):
        assert listening_ports() == []


def test_listening_ports_includes_listening_tcp4():
    with patch("fivenines_agent.ports.psutil.net_connections",
               return_value=[_tcp4("0.0.0.0", 80)]), \
         patch("fivenines_agent.ports.check_ipv6_dual_stack", return_value=True):
        result = listening_ports()
    assert (80, "TCP (IPv4)", "0.0.0.0") in result


def test_listening_ports_excludes_non_listening_tcp():
    with patch("fivenines_agent.ports.psutil.net_connections",
               return_value=[_tcp4("0.0.0.0", 80, status=psutil.CONN_ESTABLISHED)]):
        assert listening_ports() == []


def test_listening_ports_includes_udp_unconn():
    with patch("fivenines_agent.ports.psutil.net_connections",
               return_value=[_udp4("0.0.0.0", 53)]):
        result = listening_ports()
    assert (53, "UDP (IPv4)", "0.0.0.0") in result


def test_listening_ports_excludes_udp_with_state():
    """UDP sockets that report any state other than CONN_NONE are excluded."""
    with patch("fivenines_agent.ports.psutil.net_connections",
               return_value=[_udp4("0.0.0.0", 53, status=psutil.CONN_ESTABLISHED)]):
        assert listening_ports() == []


def test_listening_ports_skips_ephemeral_ports():
    with patch("fivenines_agent.ports.psutil.net_connections",
               return_value=[_tcp4("0.0.0.0", 40000)]), \
         patch("fivenines_agent.ports.get_ephemeral_port_range",
               return_value=(32768, 60999)):
        assert listening_ports() == []


def test_listening_ports_includes_monitored_ephemeral():
    with patch("fivenines_agent.ports.psutil.net_connections",
               return_value=[_tcp4("0.0.0.0", 40000)]), \
         patch("fivenines_agent.ports.get_ephemeral_port_range",
               return_value=(32768, 60999)):
        result = listening_ports(monitored_ports=[40000])
    assert (40000, "TCP (IPv4)", "0.0.0.0") in result


# --- Dual-stack post-processing ---


def test_listening_ports_marks_dual_stack_when_ipv6_all_zero_no_ipv4():
    """IPv6 socket bound to :: with no IPv4 listener and bindv6only=0 -> Dual-Stack."""
    with patch("fivenines_agent.ports.psutil.net_connections",
               return_value=[_tcp6("::", 8080)]), \
         patch("fivenines_agent.ports.check_ipv6_dual_stack", return_value=True):
        result = listening_ports()
    assert (8080, "TCP (Dual-Stack)", "::") in result


def test_listening_ports_not_dual_stack_with_explicit_ipv4():
    """IPv6 :: socket plus an explicit IPv4 listener on the same port -> NOT dual-stack."""
    with patch("fivenines_agent.ports.psutil.net_connections",
               return_value=[_tcp4("0.0.0.0", 9090), _tcp6("::", 9090)]), \
         patch("fivenines_agent.ports.check_ipv6_dual_stack", return_value=True):
        result = listening_ports()
    proto_names = {(p, n): a for p, n, a in result}
    assert (9090, "TCP (IPv6)") in proto_names
    assert (9090, "TCP (Dual-Stack)") not in proto_names


def test_listening_ports_not_dual_stack_when_bindv6only():
    """bindv6only=1 -> IPv6 stays plain TCP (IPv6) even if bound to ::."""
    with patch("fivenines_agent.ports.psutil.net_connections",
               return_value=[_tcp6("::", 7070)]), \
         patch("fivenines_agent.ports.check_ipv6_dual_stack", return_value=False):
        result = listening_ports()
    assert (7070, "TCP (IPv6)", "::") in result


def test_listening_ports_not_dual_stack_when_specific_ipv6_address():
    """IPv6 bound to a specific (non-::) address is never dual-stack."""
    with patch("fivenines_agent.ports.psutil.net_connections",
               return_value=[_tcp6("fe80::1", 6060)]), \
         patch("fivenines_agent.ports.check_ipv6_dual_stack", return_value=True):
        result = listening_ports()
    assert (6060, "TCP (IPv6)", "fe80::1") in result


# --- Edge cases ---


def test_listening_ports_skips_conn_without_laddr():
    bad = SimpleNamespace(
        fd=-1, family=socket.AF_INET, type=socket.SOCK_STREAM,
        laddr=(), raddr=(), status=psutil.CONN_LISTEN, pid=None,
    )
    with patch("fivenines_agent.ports.psutil.net_connections", return_value=[bad]):
        assert listening_ports() == []


def test_listening_ports_skips_unknown_proto():
    """Non-inet families are filtered out.

    Uses a sentinel integer family value rather than socket.AF_UNIX so the
    test runs on Windows builds where AF_UNIX isn't exposed by the stdlib
    socket module.
    """
    weird = _conn(999, socket.SOCK_STREAM, "/tmp/sock", 0, psutil.CONN_LISTEN)
    with patch("fivenines_agent.ports.psutil.net_connections", return_value=[weird]):
        assert listening_ports() == []


def test_listening_ports_access_denied_falls_back_per_kind():
    """AccessDenied on the unified call -> falls back to per-kind enumeration."""
    call_count = {"n": 0}

    def fake_net_connections(kind):
        call_count["n"] += 1
        if kind == "inet":
            raise psutil.AccessDenied()
        if kind == "tcp4":
            return [_tcp4("0.0.0.0", 22)]
        return []

    with patch("fivenines_agent.ports.psutil.net_connections", side_effect=fake_net_connections):
        result = listening_ports()
    assert (22, "TCP (IPv4)", "0.0.0.0") in result
    assert call_count["n"] >= 2  # inet (raised) + at least one per-kind


def test_listening_ports_access_denied_on_per_kind_continues():
    """One kind raising AccessDenied doesn't kill the rest."""
    def fake_net_connections(kind):
        if kind == "inet":
            raise psutil.AccessDenied()
        if kind == "tcp4":
            raise psutil.AccessDenied()
        if kind == "tcp6":
            return [_tcp6("::1", 25)]
        return []

    with patch("fivenines_agent.ports.psutil.net_connections", side_effect=fake_net_connections), \
         patch("fivenines_agent.ports.check_ipv6_dual_stack", return_value=False), \
         patch("fivenines_agent.ports.get_ephemeral_port_range", return_value=(40000, 60000)):
        result = listening_ports()
    assert (25, "TCP (IPv6)", "::1") in result


# --- get_ephemeral_port_range + check_ipv6_dual_stack ---


def test_get_ephemeral_port_range_reads_proc():
    with patch("builtins.open", mock_open(read_data="20000\t60999\n")):
        assert get_ephemeral_port_range() == (20000, 60999)


def test_get_ephemeral_port_range_fallback_on_missing_file():
    def fake_open(*args, **kwargs):
        raise FileNotFoundError
    with patch.object(builtins, "open", fake_open):
        assert get_ephemeral_port_range() == (32768, 60999)


def test_get_ephemeral_port_range_fallback_on_garbage():
    with patch("builtins.open", mock_open(read_data="garbage")):
        assert get_ephemeral_port_range() == (32768, 60999)


def test_check_ipv6_dual_stack_zero_means_dual_stack():
    with patch("builtins.open", mock_open(read_data="0\n")):
        assert check_ipv6_dual_stack() is True


def test_check_ipv6_dual_stack_one_means_no():
    with patch("builtins.open", mock_open(read_data="1\n")):
        assert check_ipv6_dual_stack() is False


def test_check_ipv6_dual_stack_missing_file_defaults_true():
    def fake_open(*args, **kwargs):
        raise FileNotFoundError
    with patch.object(builtins, "open", fake_open):
        assert check_ipv6_dual_stack() is True


def test_protocols_dict_keys_unchanged():
    """The PROTOCOLS mapping is part of the output contract; keys must not drift."""
    assert set(PROTOCOLS.keys()) == {"tcp", "tcp6", "udp", "udp6"}
    assert PROTOCOLS["tcp"] == "TCP (IPv4)"
    assert PROTOCOLS["tcp6"] == "TCP (IPv6)"
    assert PROTOCOLS["udp"] == "UDP (IPv4)"
    assert PROTOCOLS["udp6"] == "UDP (IPv6)"
