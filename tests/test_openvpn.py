"""Unit tests for the OpenVPN management-socket collector (agent #145).

The cross-repo payload shape lives in test_openvpn_contract.py. This file
covers the transport, the protocol reader and every failure path.

WINDOWS: the full suite runs on windows-latest, which has no socket.AF_UNIX.
Tests that need the happy path INJECT the attribute and mock socket.socket so
they run everywhere; the one test that opens a real unix socket is skipped
there, and a dedicated test pins the "no AF_UNIX" behaviour by deleting it.
"""

import os
import shutil
import socket
import tempfile
import threading
import time

import pytest

from fivenines_agent import openvpn

GREETING = (
    b">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n"
)

VERSION_ANSWER = (
    "OpenVPN Version: OpenVPN 2.6.14 x86_64-pc-linux-gnu [SSL (OpenSSL)] "
    "[LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]\n"
    "Management Version: 5\n"
    "END\n"
)

STATUS_HEADER = (
    "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\t"
    "Virtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\t"
    "Connected Since (time_t)\tUsername\tClient ID\tPeer ID\t"
    "Data Channel Cipher\n"
)


def _server_status(rows="", now=1000, time_t=None):
    time_t = now - 2 if time_t is None else time_t
    return (
        "TITLE\tOpenVPN 2.6.14 x86_64-pc-linux-gnu [SSL (OpenSSL)]\n"
        f"TIME\t2026-09-11 18:57:00\t{time_t}\n"
        + STATUS_HEADER
        + rows
        + "HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\n"
        + "GLOBAL_STATS\tMax bcast/mcast queue length\t0\n"
        "END\n"
    )


def _client_row(
    cn="site-lyon",
    real="203.0.113.5:51820",
    virt="10.8.0.6",
    rx=1234,
    tx=5678,
    since=1000,
    user="UNDEF",
    cipher="AES-256-GCM",
):
    return (
        f"CLIENT_LIST\t{cn}\t{real}\t{virt}\t\t{rx}\t{tx}\t"
        f"2026-09-10 18:57:00\t{since}\t{user}\t0\t0\t{cipher}\n"
    )


class FakeSocket:
    """Scripted management connection.

    `answers` maps a command to the bytes it replies with; `initial` is what is
    already readable before anything is sent (the greeting). A command with no
    scripted answer replies with nothing, which the reader sees as EOF.
    """

    def __init__(
        self, answers=None, initial=GREETING, recv_error=None, send_error=None
    ):
        self.answers = answers or {}
        self.pending = bytearray(initial)
        self.recv_error = recv_error
        self.send_error = send_error
        self.sent = []
        self.closed = False
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def sendall(self, data):
        if self.send_error is not None:
            raise self.send_error
        command = data.decode().strip()
        self.sent.append(command)
        answer = self.answers.get(command)
        if answer is not None:
            self.pending += answer.encode()

    def recv(self, size):
        if self.recv_error is not None:
            raise self.recv_error
        chunk = bytes(self.pending[:size])
        del self.pending[:size]
        return chunk

    def close(self):
        self.closed = True


def _management(sock, budget=5):
    return openvpn._Management(sock, time.monotonic() + budget)


# Windows ignores POSIX mode bits on directories: chmod(0o000) succeeds and
# os.access(dir, R_OK | X_OK) still returns True, so nothing is ever "blind"
# there. These tests exercise the collector's blind-vs-empty rule, which is a
# POSIX filesystem concept -- and the collector is Linux-only by design (its
# RUNTIME_DIRS are /run/... and the server strips the key for Windows agents).
# The full suite runs on windows-latest in CI, so the guard has to be explicit.
_needs_posix_permissions = pytest.mark.skipif(
    os.name != "posix",
    reason="directory permission bits are POSIX-only; Windows ignores chmod on dirs",
)


@pytest.fixture(autouse=True)
def _reset_module_state():
    """The process-scan cache and the rotation counter are module state.

    Left alone they leak between tests -- a cached "no openvpn here" answer from
    one test silently satisfies the next, which is the shape of a test that
    passes for the wrong reason.
    """
    openvpn._process_scan_at = 0.0
    openvpn._process_scan_result = None
    openvpn._rotation = 0
    yield
    openvpn._process_scan_at = 0.0
    openvpn._process_scan_result = None
    openvpn._rotation = 0


# --- discovery -------------------------------------------------------------


def test_discover_sockets_is_sorted_and_deduplicated(monkeypatch):
    monkeypatch.setattr(openvpn, "RUNTIME_DIRS", ("/run/a", "/run/b"))
    listing = {
        "/run/a/*.sock": ["/run/a/z.sock", "/run/a/a.sock"],
        "/run/b/*.sock": ["/run/b/link.sock"],
    }
    monkeypatch.setattr(openvpn.glob, "glob", lambda pattern: listing[pattern])
    monkeypatch.setattr(openvpn, "_is_socket", lambda _p: True)
    # /run/b/link.sock is a symlink to the socket already found in /run/a --
    # the shape a host gets when /var/run is a symlink to /run.
    monkeypatch.setattr(
        openvpn.os.path,
        "realpath",
        lambda p: "/run/a/a.sock" if p == "/run/b/link.sock" else p,
    )
    assert openvpn._discover_sockets() == (["/run/a/a.sock", "/run/a/z.sock"], [])


def test_discover_sockets_uses_forward_slashes(monkeypatch):
    """Linux-only paths must never go through os.path.join (ntpath on Windows
    would build /run/openvpn-server\\*.sock)."""
    seen = []
    monkeypatch.setattr(
        openvpn.glob, "glob", lambda pattern: seen.append(pattern) or []
    )
    openvpn._discover_sockets()
    assert seen == [f"{d}/*.sock" for d in openvpn.RUNTIME_DIRS]
    assert all("\\" not in p for p in seen)


class _FakeProcess:
    def __init__(self, name):
        self.info = {"name": name}


def test_openvpn_is_running_detects_the_daemon(monkeypatch):
    monkeypatch.setattr(
        openvpn.psutil,
        "process_iter",
        lambda _attrs: [_FakeProcess("sshd"), _FakeProcess("OpenVPN")],
    )
    assert openvpn._openvpn_is_running() is True


def test_openvpn_is_running_tolerates_a_nameless_process(monkeypatch):
    monkeypatch.setattr(
        openvpn.psutil,
        "process_iter",
        lambda _attrs: [_FakeProcess(None), _FakeProcess("cron")],
    )
    assert openvpn._openvpn_is_running() is False


def test_openvpn_is_running_matches_the_windows_process_name(monkeypatch):
    """openvpn.exe is in the set on purpose.

    The collector is Linux-only (Windows OpenVPN has TCP management only), so a
    Windows host can never find a socket. Recognising the process there is what
    keeps it reporting null -- 'we cannot read this' -- instead of
    {'instances': []}, which is the documented prune-all.
    """
    monkeypatch.setattr(
        openvpn.psutil, "process_iter", lambda _attrs: [_FakeProcess("OpenVPN.exe")]
    )
    assert openvpn._openvpn_is_running() is True


# --- protocol reader -------------------------------------------------------


def test_command_skips_async_notifications():
    """`>`-prefixed real-time notifications may be interleaved at any point."""
    sock = FakeSocket(
        answers={
            "status 3": ">CLIENT:ESTABLISHED,0\nTITLE\tx\n>LOG:1,I,something\nEND\n"
        }
    )
    assert _management(sock).command("status 3") == ["TITLE\tx"]


def test_command_returns_on_success_line():
    sock = FakeSocket(answers={"state": "SUCCESS: state set\n"})
    assert _management(sock).command("state") == []


def test_command_raises_on_error_line():
    sock = FakeSocket(answers={"status 3": "ERROR: unknown command\n"})
    with pytest.raises(openvpn._InstanceError) as excinfo:
        _management(sock).command("status 3")
    assert "unknown command" in str(excinfo.value)


def test_answer_without_end_is_an_error_not_a_short_list():
    """The acceptance case: a socket that answers without END must never
    degrade into a truncated client list."""
    sock = FakeSocket(answers={"status 3": _server_status(_client_row())[:-4]})
    with pytest.raises(openvpn._InstanceError) as excinfo:
        _management(sock).command("status 3")
    assert "closed before END" in str(excinfo.value)


def test_eof_before_the_greeting_is_the_group_rejection():
    """Measured shape of a management-client-group mismatch: connect succeeds,
    then the daemon closes without sending a byte."""
    sock = FakeSocket(initial=b"")
    with pytest.raises(openvpn._InstanceError) as excinfo:
        _management(sock).command("version")
    assert excinfo.value.args[0] == openvpn._REJECTED_REASON


def test_send_failure_before_any_byte_is_also_the_rejection():
    sock = FakeSocket(initial=b"", send_error=BrokenPipeError("EPIPE"))
    with pytest.raises(openvpn._InstanceError) as excinfo:
        _management(sock).command("version")
    assert excinfo.value.args[0] == openvpn._REJECTED_REASON


def test_send_failure_after_the_greeting_is_a_socket_error():
    sock = FakeSocket(send_error=BrokenPipeError("EPIPE"))
    client = _management(sock)
    client.read_greeting()
    with pytest.raises(openvpn._InstanceError) as excinfo:
        client.command("version")
    assert "socket error" in str(excinfo.value)


def test_password_prompt_is_named_rather_than_a_generic_timeout():
    """The daemon writes the prompt with NO newline, so the read just stalls.
    The agent never sends a password, so the reason has to say so."""
    sock = FakeSocket(initial=b"ENTER PASSWORD:")
    with pytest.raises(openvpn._InstanceError) as excinfo:
        _management(sock).command("version")
    assert "management password required" in str(excinfo.value)


class _StallingSocket(FakeSocket):
    """Delivers what it has, then stalls with the connection still open."""

    def recv(self, size):
        chunk = super().recv(size)
        if not chunk:
            raise socket.timeout("timed out")
        return chunk


def test_password_prompt_is_named_even_when_the_socket_only_stalls():
    """The other half of the password case, and the one a live instance really
    produces.

    The daemon writes 'ENTER PASSWORD:' with NO trailing newline and then WAITS
    -- it does not close -- so the read ends in a timeout rather than the EOF
    the test above simulates. Both paths go through _stall_reason; if only the
    EOF one did, a password-protected instance would report a bare 'timed out'
    and the operator would go hunting for a wedged daemon that is not wedged.
    """
    sock = _StallingSocket(initial=b"ENTER PASSWORD:")
    with pytest.raises(openvpn._InstanceError) as excinfo:
        _management(sock).command("version")
    assert "management password required" in str(excinfo.value)


def test_read_timeout_is_reported():
    sock = FakeSocket(recv_error=socket.timeout("timed out"))
    with pytest.raises(openvpn._InstanceError) as excinfo:
        _management(sock).command("version")
    assert excinfo.value.args[0] == "timed out"


def test_socket_error_while_reading_is_reported():
    sock = FakeSocket(recv_error=ConnectionResetError("reset"))
    with pytest.raises(openvpn._InstanceError) as excinfo:
        _management(sock).command("version")
    assert "socket error" in str(excinfo.value)


def test_expired_deadline_raises_before_reading():
    sock = FakeSocket()
    client = openvpn._Management(sock, time.monotonic() - 1)
    with pytest.raises(openvpn._InstanceError) as excinfo:
        client.command("version")
    assert excinfo.value.args[0] == "timed out"


def test_byte_cap_errors_the_instance(monkeypatch):
    monkeypatch.setattr(openvpn, "_MAX_RESPONSE_BYTES", 16)
    sock = FakeSocket(initial=b"x" * 64)
    with pytest.raises(openvpn._InstanceError) as excinfo:
        _management(sock).command("version")
    assert "byte cap" in str(excinfo.value)


def test_quit_swallows_a_send_failure():
    sock = FakeSocket(send_error=OSError("gone"))
    _management(sock).quit()  # must not raise


def test_carriage_returns_are_stripped():
    sock = FakeSocket(
        answers={"version": "OpenVPN Version: OpenVPN 2.6.14 x\r\nEND\r\n"}
    )
    assert _management(sock).command("version") == ["OpenVPN Version: OpenVPN 2.6.14 x"]


class _ChunkedSocket(FakeSocket):
    """Hands back a few bytes at a time, the way a real socket does."""

    chunk = 7

    def recv(self, size):
        return super().recv(min(size, self.chunk))


def test_lines_split_across_recv_chunks_are_reassembled():
    """A real answer arrives in kernel-sized pieces, not one tidy blob.

    Every other test in this file scripts a socket that returns the whole answer
    in a single recv, so nothing else exercises the buffer that carries a
    half-line from one _fill to the next -- and a reader that dropped it would
    lose CLIENT_LIST rows on exactly the large servers where the answer needs
    several chunks.
    """
    sock = _ChunkedSocket(
        answers={"version": VERSION_ANSWER, "status 3": _server_status(_client_row())}
    )
    client = _management(sock)
    assert openvpn._parse_version(client.command("version")) == "OpenVPN 2.6.14"
    mode, _age, rows = openvpn._parse_status(client.command("status 3"), 1000)
    assert (mode, len(rows)) == ("server", 1)
    assert rows[0]["Common Name"] == "site-lyon"


# --- field parsing ---------------------------------------------------------


def test_cell_separates_absent_column_from_undef_value():
    """null means 'this OpenVPN has no such column'; '' means 'it reported
    nothing'. Two different operator actions."""
    assert openvpn._cell({}, "Username") is None
    assert openvpn._cell({"Username": "UNDEF"}, "Username") == ""
    assert openvpn._cell({"Username": " "}, "Username") == ""
    assert openvpn._cell({"Username": " ops "}, "Username") == "ops"


def test_cell_bounds_an_absurd_value():
    huge = "x" * (openvpn._MAX_FIELD_CHARS * 3)
    assert len(openvpn._cell({"Common Name": huge}, "Common Name")) == (
        openvpn._MAX_FIELD_CHARS
    )


@pytest.mark.parametrize(
    "value,expected", [(None, None), ("", None), ("nope", None), (" 42 ", 42)]
)
def test_as_int(value, expected):
    assert openvpn._as_int(value) == expected


def test_age_is_none_for_an_unreadable_timestamp():
    assert openvpn._age(None, 1000) is None
    assert openvpn._age("nope", 1000) is None


def test_age_is_none_never_zero_when_the_clock_stepped_backwards():
    """A 0 would tell the server the session just connected and would silently
    reset the uptime of a tunnel that has been up for months."""
    assert openvpn._age("2000", 1000) is None
    assert openvpn._age("900", 1000) == 100


def test_version_banner_is_trimmed_to_two_tokens():
    lines = VERSION_ANSWER.splitlines()
    assert openvpn._parse_version(lines) == "OpenVPN 2.6.14"


def test_version_is_none_when_absent_or_empty():
    assert openvpn._parse_version(["Management Version: 5"]) is None
    assert openvpn._parse_version(["OpenVPN Version:   "]) is None


# --- status parsing --------------------------------------------------------


def test_server_mode_is_identified_by_the_client_list_header():
    mode, age, rows = openvpn._parse_status(
        _server_status(_client_row(), time_t=998).splitlines(), 1000
    )
    assert (mode, age) == ("server", 2)
    assert rows[0]["Common Name"] == "site-lyon"


def test_a_server_with_zero_clients_is_still_server_mode():
    """The HEADER line is emitted unconditionally, which is what makes the
    discriminator safe."""
    mode, _age, rows = openvpn._parse_status(_server_status().splitlines(), 1000)
    assert (mode, rows) == ("server", [])


def test_client_mode_is_identified_by_the_statistics_banner():
    answer = (
        "OpenVPN STATISTICS\n"
        "Updated,2026-09-11 18:57:01\n"
        "TCP/UDP read bytes,1572\n"
        "END\n"
    )
    assert openvpn._parse_status(answer.splitlines(), 1000) == ("client", None, [])


def test_an_unrecognized_status_answer_errors_the_instance():
    """Never assume 'no client list' means client mode: a server whose answer
    we mis-read would render as a healthy client with zero sessions."""
    with pytest.raises(openvpn._InstanceError) as excinfo:
        openvpn._parse_status(["something else entirely"], 1000)
    assert "unrecognized" in str(excinfo.value)


def test_client_list_row_before_its_header_is_refused():
    with pytest.raises(openvpn._InstanceError) as excinfo:
        openvpn._parse_status([_client_row().rstrip("\n")], 1000)
    assert "before its HEADER" in str(excinfo.value)


def test_client_list_row_with_the_wrong_field_count_is_refused():
    """Header and row come from the same daemon in the same answer, so a
    mismatch means the format is not what we think it is -- and mapping the
    cells anyway would feed shifted values into the byte counters."""
    broken = _server_status("CLIENT_LIST\tsite-lyon\t203.0.113.5:51820\n")
    with pytest.raises(openvpn._InstanceError) as excinfo:
        openvpn._parse_status(broken.splitlines(), 1000)
    assert "HEADER declares" in str(excinfo.value)


def test_routing_table_rows_are_ignored():
    """They are a second view of the same sessions; folding them in would
    double-count under duplicate-cn."""
    answer = _server_status(_client_row()) + "ROUTING_TABLE\t10.8.0.6\tsite-lyon\n"
    _mode, _age, rows = openvpn._parse_status(answer.splitlines(), 1000)
    assert len(rows) == 1


def test_a_malformed_time_line_leaves_the_age_null():
    answer = _server_status().replace("TIME\t2026-09-11 18:57:00\t998", "TIME\tx")
    _mode, age, _rows = openvpn._parse_status(answer.splitlines(), 1000)
    assert age is None


# --- duplicate-cn collapse -------------------------------------------------


def _rows(*specs):
    answer = _server_status("".join(specs))
    _mode, _age, rows = openvpn._parse_status(answer.splitlines(), 100000)
    return rows


def test_duplicate_cn_sessions_collapse():
    clients = openvpn._collapse_clients(
        _rows(
            _client_row(
                real="198.51.100.23:41001",
                virt="10.8.0.7",
                rx=1000,
                tx=2000,
                since=99880,
            ),
            _client_row(
                real="203.0.113.5:51820", virt="10.8.0.6", rx=1234, tx=5678, since=13600
            ),
        ),
        100000,
    )
    assert len(clients) == 1
    entry = clients[0]
    assert entry["sessions"] == 2
    assert (entry["bytes_received"], entry["bytes_sent"]) == (2234, 7678)
    # The OLDEST session, which is listed SECOND here.
    assert entry["connected_age_s"] == 86400
    assert entry["real_address"] == "203.0.113.5:51820"
    assert entry["virtual_address"] == "10.8.0.6"


def test_collapse_keeps_the_first_row_on_an_age_tie():
    clients = openvpn._collapse_clients(
        _rows(
            _client_row(real="first:1", since=99000),
            _client_row(real="second:2", since=99000),
        ),
        100000,
    )
    assert clients[0]["real_address"] == "first:1"
    assert clients[0]["sessions"] == 2


def test_collapse_handles_sessions_with_no_readable_age():
    clients = openvpn._collapse_clients(
        _rows(
            _client_row(since="bogus", real="first:1"),
            _client_row(since=99000, real="second:2"),
        ),
        100000,
    )
    entry = clients[0]
    assert entry["connected_age_s"] == 1000
    # The only session with a real age becomes the reference row.
    assert entry["real_address"] == "second:2"


def test_collapse_leaves_the_age_null_when_no_session_has_one():
    clients = openvpn._collapse_clients(
        _rows(_client_row(since="bogus"), _client_row(since="also-bogus")), 100000
    )
    assert clients[0]["connected_age_s"] is None


def test_distinct_common_names_stay_separate():
    clients = openvpn._collapse_clients(
        _rows(_client_row(cn="site-lyon"), _client_row(cn="site-paris")), 100000
    )
    assert [c["common_name"] for c in clients] == ["site-lyon", "site-paris"]


def test_add_tolerates_absent_counters():
    assert openvpn._add(None, 5) == 5
    assert openvpn._add(5, None) == 5
    assert openvpn._add(2, 3) == 5


# A pre-2.4 daemon's CLIENT_LIST header: no Username, no Client ID / Peer ID,
# no Data Channel Cipher, and -- the part a positional reader trips on -- no
# Virtual IPv6 Address column either, so every counter sits at a different
# index than it does in the 2.6 header used everywhere else in this file.
_OLD_HEADER = (
    "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\t"
    "Bytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\n"
)


def test_an_older_daemons_columns_are_read_by_name_not_by_position():
    """The HAProxy CSV lesson, on the version range it actually bites.

    The column set grew across OpenVPN 2.x, so a positional read would map this
    daemon's 'Bytes Received' out of the Virtual IPv6 slot and feed shifted
    values into the counters the server rates. Nothing else here varies the
    header, so nothing else would catch that.

    It also pins the null-vs-empty rule end to end: a column this daemon does
    not HAVE is null ('upgrade OpenVPN to see it'), which is a different
    operator action from the '' a present-but-unset column reports.
    """
    answer = (
        "TIME\t2026-09-11 18:57:00\t998\n"
        + _OLD_HEADER
        + "CLIENT_LIST\tsite-lyon\t203.0.113.5:51820\t10.8.0.6\t1234\t5678\t"
        "2026-09-10 18:57:00\t900\n"
    )
    mode, status_age, rows = openvpn._parse_status(answer.splitlines(), 1000)
    assert (mode, status_age) == ("server", 2)

    assert openvpn._collapse_clients(rows, 1000) == [
        {
            "common_name": "site-lyon",
            "identity_source": "cn",
            "real_address": "203.0.113.5:51820",
            "virtual_address": "10.8.0.6",
            "username": None,
            "sessions": 1,
            "connected_age_s": 100,
            "bytes_received": 1234,
            "bytes_sent": 5678,
            "cipher": None,
        }
    ]


# --- state parsing ---------------------------------------------------------


def test_state_is_parsed_from_the_comma_separated_answer():
    assert openvpn._parse_state(
        ["1789152900,CONNECTED,SUCCESS,10.8.0.2,198.51.100.7,1194,,"], 1789153020
    ) == {
        "name": "CONNECTED",
        "description": "SUCCESS",
        "local_ip": "10.8.0.2",
        "remote": "198.51.100.7:1194",
        "age_s": 120,
    }


def test_state_falls_back_to_the_ipv6_local_address():
    parsed = openvpn._parse_state(
        ["1000,CONNECTED,SUCCESS,,198.51.100.7,1194,,,2001:db8::1"], 1000
    )
    assert parsed["local_ip"] == "2001:db8::1"


def test_state_without_a_remote_port_reports_the_address_alone():
    parsed = openvpn._parse_state(["1000,WAIT,,10.8.0.2,198.51.100.7"], 1000)
    assert parsed["remote"] == "198.51.100.7"
    assert parsed["description"] is None


def test_state_before_any_address_is_assigned():
    parsed = openvpn._parse_state(["1000,CONNECTING,,,,,,"], 1000)
    assert parsed == {
        "name": "CONNECTING",
        "description": None,
        "local_ip": None,
        "remote": None,
        "age_s": 0,
    }


def test_state_is_none_when_the_answer_carries_none():
    assert openvpn._parse_state([], 1000) is None
    assert openvpn._parse_state(["1000"], 1000) is None
    assert openvpn._parse_state(["1000,"], 1000) is None


# --- connect ---------------------------------------------------------------


def test_connect_without_af_unix_is_an_instance_error(monkeypatch):
    monkeypatch.delattr(openvpn.socket, "AF_UNIX", raising=False)
    with pytest.raises(openvpn._InstanceError) as excinfo:
        openvpn._connect("/run/openvpn-server/x.sock", time.monotonic() + 5)
    assert "unix sockets are unavailable" in str(excinfo.value)


def test_connect_failure_is_an_instance_error(monkeypatch):
    monkeypatch.setattr(openvpn.socket, "AF_UNIX", 1, raising=False)
    fake = FakeSocket()

    def boom(*_args, **_kwargs):
        raise PermissionError("Permission denied")

    fake.connect = boom
    monkeypatch.setattr(openvpn.socket, "socket", lambda *_a, **_k: fake)
    with pytest.raises(openvpn._InstanceError) as excinfo:
        openvpn._connect("/run/openvpn-server/x.sock", time.monotonic() + 5)
    assert "connect failed" in str(excinfo.value)
    # The socket is closed even on the failing path.
    assert fake.closed is True


def test_connect_clamps_the_timeout_to_the_remaining_budget(monkeypatch):
    monkeypatch.setattr(openvpn.socket, "AF_UNIX", 1, raising=False)
    fake = FakeSocket()
    fake.connect = lambda _path: None
    monkeypatch.setattr(openvpn.socket, "socket", lambda *_a, **_k: fake)
    openvpn._connect("/run/openvpn-server/x.sock", time.monotonic() + 1)
    assert 0 < fake.timeouts[0] <= 1


def test_connect_gives_up_before_opening_a_socket_once_the_budget_is_spent(
    monkeypatch,
):
    """settimeout(0) would put a real socket in NON-BLOCKING mode and surface
    the spent budget as an EAGAIN, so the socket is never opened at all."""
    monkeypatch.setattr(openvpn.socket, "AF_UNIX", 1, raising=False)
    opened = []
    monkeypatch.setattr(
        openvpn.socket, "socket", lambda *_a, **_k: opened.append(1) or FakeSocket()
    )
    with pytest.raises(openvpn._InstanceError) as excinfo:
        openvpn._connect("/run/openvpn-server/x.sock", time.monotonic() - 10)
    assert excinfo.value.args[0] == "timed out"
    assert opened == []


# --- whole-collector outcomes ----------------------------------------------


def _collect(monkeypatch, paths, sockets, running=False, now=1000):
    monkeypatch.setattr(openvpn.time, "time", lambda: now)
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: (list(paths), []))
    monkeypatch.setattr(openvpn, "_openvpn_is_running", lambda: running)
    monkeypatch.setattr(openvpn, "_connect", lambda path, _deadline: sockets[path])
    return openvpn.openvpn_metrics()


def test_a_host_with_no_openvpn_reports_an_empty_instance_list(monkeypatch):
    assert _collect(monkeypatch, [], {}, running=False) == {"instances": []}


def test_a_running_daemon_with_no_socket_is_a_collection_failure(monkeypatch):
    """The acceptance case: never {'instances': []}, which would prune every
    instance row for a VPN that is up and carrying traffic."""
    assert _collect(monkeypatch, [], {}, running=True) is None


def test_a_failing_glob_is_a_collection_failure(monkeypatch):
    def boom():
        raise OSError("permission denied")

    monkeypatch.setattr(openvpn, "_discover_sockets", boom)
    assert openvpn.openvpn_metrics() is None


def test_a_failing_process_scan_is_a_collection_failure(monkeypatch):
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: ([], []))

    def boom():
        raise RuntimeError("psutil exploded")

    monkeypatch.setattr(openvpn, "_openvpn_is_running", boom)
    assert openvpn.openvpn_metrics() is None


def test_too_many_sockets_fails_the_tick_rather_than_truncating(monkeypatch):
    """A short instances array is indistinguishable from a shrunken one."""
    monkeypatch.setattr(openvpn, "_MAX_INSTANCES", 2)
    paths = [f"/run/openvpn-server/i{i}.sock" for i in range(3)]
    assert _collect(monkeypatch, paths, {}) is None


def test_one_unreadable_instance_does_not_poison_the_others(monkeypatch):
    good = "/run/openvpn-server/server.sock"
    bad = "/run/openvpn/legacy.sock"
    sockets = {
        good: FakeSocket(
            answers={
                "version": VERSION_ANSWER,
                "status 3": _server_status(_client_row(since=900), time_t=998),
            }
        ),
        bad: FakeSocket(initial=b""),
    }
    result = _collect(monkeypatch, [good, bad], sockets)
    assert [i["name"] for i in result["instances"]] == ["server", "legacy"]
    assert result["instances"][0]["clients"][0]["connected_age_s"] == 100
    assert result["instances"][1] == {
        "name": "legacy",
        "socket": bad,
        "error": openvpn._REJECTED_REASON,
    }
    assert "clients" not in result["instances"][1]


def test_an_unexpected_fault_costs_one_instance_not_the_host(monkeypatch):
    good = "/run/openvpn-server/server.sock"
    bad = "/run/openvpn-server/odd.sock"
    sockets = {
        good: FakeSocket(
            answers={"version": VERSION_ANSWER, "status 3": _server_status()}
        )
    }

    def connect(path, _deadline):
        if path == bad:
            raise ZeroDivisionError("something nobody predicted")
        return sockets[path]

    monkeypatch.setattr(openvpn.time, "time", lambda: 1000)
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: ([good, bad], []))
    monkeypatch.setattr(openvpn, "_connect", connect)
    result = openvpn.openvpn_metrics()
    assert result["instances"][0]["mode"] == "server"
    assert "ZeroDivisionError" in result["instances"][1]["error"]


def test_the_collection_deadline_errors_the_instances_it_cannot_reach(monkeypatch):
    """Instances past the budget are still LISTED -- dropping them would read
    as a prune."""
    monkeypatch.setattr(openvpn, "_COLLECT_DEADLINE", -1)
    path = "/run/openvpn-server/server.sock"
    sockets = {path: FakeSocket()}
    result = _collect(monkeypatch, [path], sockets)
    assert result["instances"][0]["error"] == "timed out"
    assert "clients" not in result["instances"][0]


def test_every_instance_unreadable_is_still_an_instance_list(monkeypatch):
    """The host that named the WRONG management-client-group: every socket
    connects and every daemon drops it.

    That is a list of per-instance nulls, not a host-wide null. Each entry names
    its socket and its reason, which is what freezes that instance's rows and
    keeps its trigger open; collapsing them into null would discard both the
    reasons and the knowledge that these instances exist at all -- the server
    skips a null outright.
    """
    first = "/run/openvpn-server/a.sock"
    second = "/run/openvpn-server/b.sock"
    sockets = {first: FakeSocket(initial=b""), second: FakeSocket(initial=b"")}
    result = _collect(monkeypatch, [first, second], sockets, running=True)

    assert result == {
        "instances": [
            {"name": "a", "socket": first, "error": openvpn._REJECTED_REASON},
            {"name": "b", "socket": second, "error": openvpn._REJECTED_REASON},
        ]
    }


def test_a_host_sitting_exactly_on_the_instance_cap_still_reports(monkeypatch):
    """Off-by-one guard: the tick fails ABOVE the ceiling, not on it.

    A `>=` here would take an MSP box with exactly _MAX_INSTANCES instances
    permanently dark, and a host-wide null is the one outcome that reports
    nothing at all.
    """
    monkeypatch.setattr(openvpn, "_MAX_INSTANCES", 2)
    paths = [f"/run/openvpn-server/i{i}.sock" for i in range(2)]
    answers = {"version": VERSION_ANSWER, "status 3": _server_status()}
    sockets = {path: FakeSocket(answers=dict(answers)) for path in paths}
    result = _collect(monkeypatch, paths, sockets)
    assert [i["name"] for i in result["instances"]] == ["i0", "i1"]


class _SlowSocket(FakeSocket):
    """A daemon that answers correctly but takes real time doing it."""

    def __init__(self, clock, step, **kwargs):
        super().__init__(**kwargs)
        self._clock = clock
        self._step = step

    def recv(self, size):
        self._clock["now"] += self._step
        return super().recv(size)


def test_the_wall_clock_budget_is_global_not_per_instance(monkeypatch):
    """A host with several slow daemons must not multiply _SOCKET_TIMEOUT.

    Each instance here answers inside its own 5s ceiling, so a per-instance
    budget would let every one of them through and stretch the tick without
    bound -- past WatchdogSec=90 on a box with enough instances. The single
    _COLLECT_DEADLINE is what stops it: the first instance reports, the second
    runs out of the shared budget mid-read and is LISTED with an error rather
    than dropped.
    """
    clock = {"now": 0.0}
    monkeypatch.setattr(openvpn.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(openvpn, "_COLLECT_DEADLINE", 9)
    first = "/run/openvpn-server/first.sock"
    second = "/run/openvpn-server/second.sock"
    answers = {"version": VERSION_ANSWER, "status 3": _server_status()}
    sockets = {
        first: _SlowSocket(clock, 4, answers=dict(answers)),
        second: _SlowSocket(clock, 4, answers=dict(answers)),
    }

    result = _collect(monkeypatch, [first, second], sockets)

    assert result["instances"][0]["mode"] == "server"
    assert result["instances"][1] == {
        "name": "second",
        "socket": second,
        "error": "timed out",
    }


CLIENT_STATUS = (
    "OpenVPN STATISTICS\n"
    "Updated,2026-09-11 18:57:01\n"
    "TCP/UDP read bytes,1572\n"
    "TCP/UDP write bytes,1808\n"
)


def test_a_client_instance_reports_the_state_that_shows_a_down_tunnel(monkeypatch):
    """The signal the whole client-mode branch exists for.

    A server's state machine sits at CONNECTED forever, so `state` is asked only
    of a client -- and RECONNECTING with the disconnect reason in its
    description is how a dropped site-to-site tunnel surfaces. The contract
    fixture only carries a healthy CONNECTED client, so without this the unhappy
    state never travels through the collector at all.
    """
    path = "/run/openvpn-client/office.sock"
    sock = FakeSocket(
        answers={
            "version": VERSION_ANSWER,
            "status 3": CLIENT_STATUS + "END\n",
            "state": "1000,RECONNECTING,tls-error,,,,,\nEND\n",
        }
    )
    result = _collect(monkeypatch, [path], {path: sock}, now=1060)

    instance = result["instances"][0]
    assert instance["mode"] == "client"
    assert instance["clients"] == []
    assert instance["status_age_s"] is None
    assert instance["state"] == {
        "name": "RECONNECTING",
        "description": "tls-error",
        "local_ip": None,
        "remote": None,
        "age_s": 60,
    }
    assert sock.sent == ["version", "status 3", "state", "quit"]


def test_the_instance_name_drops_the_socket_extension():
    assert openvpn._instance_name("/run/openvpn-server/customer-a.sock") == "customer-a"


def test_sockets_are_closed_after_a_successful_read(monkeypatch):
    path = "/run/openvpn-server/server.sock"
    sock = FakeSocket(answers={"version": VERSION_ANSWER, "status 3": _server_status()})
    _collect(monkeypatch, [path], {path: sock})
    assert sock.closed is True
    assert sock.sent == ["version", "status 3", "quit"]


# --- capability probe ------------------------------------------------------


def test_probe_reports_the_hint_case_when_no_socket_exists(monkeypatch):
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: ([], []))
    available, reason = openvpn.probe_management_access()
    assert available is False
    assert "no management socket" in reason


def test_probe_reports_a_failing_glob(monkeypatch):
    def boom():
        raise OSError("nope")

    monkeypatch.setattr(openvpn, "_discover_sockets", boom)
    available, reason = openvpn.probe_management_access()
    assert available is False
    assert "could not list the runtime directories" in reason


def test_probe_succeeds_on_the_greeting_without_sending_a_command(monkeypatch):
    path = "/run/openvpn-server/server.sock"
    sock = FakeSocket()
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: ([path], []))
    monkeypatch.setattr(openvpn, "_connect", lambda _p, _d: sock)
    assert openvpn.probe_management_access() == (True, None)
    # The light-probe posture: nothing is ever written to the socket.
    assert sock.sent == []
    assert sock.closed is True


def test_probe_reports_the_rejection_rather_than_a_bare_connect(monkeypatch):
    """The measured trap: the socket is mode 0777, so connect() succeeds for
    every local user. A connect-only probe would report AVAILABLE here."""
    path = "/run/openvpn-server/server.sock"
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: ([path], []))
    monkeypatch.setattr(openvpn, "_connect", lambda _p, _d: FakeSocket(initial=b""))
    available, reason = openvpn.probe_management_access()
    assert available is False
    assert openvpn._REJECTED_REASON in reason


def test_probe_keeps_the_first_reason_and_tries_every_socket(monkeypatch):
    first = "/run/openvpn-server/a.sock"
    second = "/run/openvpn-server/b.sock"
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: ([first, second], []))

    def connect(path, _deadline):
        if path == first:
            raise openvpn._InstanceError("connect failed: Permission denied")
        return FakeSocket()

    monkeypatch.setattr(openvpn, "_connect", connect)
    # The second socket answers, so the capability IS available.
    assert openvpn.probe_management_access() == (True, None)


def test_probe_reports_the_first_failure_when_none_answer(monkeypatch):
    first = "/run/openvpn-server/a.sock"
    second = "/run/openvpn-server/b.sock"
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: ([first, second], []))

    def connect(path, _deadline):
        raise openvpn._InstanceError(f"connect failed: EACCES on {path}")

    monkeypatch.setattr(openvpn, "_connect", connect)
    available, reason = openvpn.probe_management_access()
    assert available is False
    assert first in reason and second not in reason


def test_probe_rejects_a_socket_that_is_not_openvpn(monkeypatch):
    path = "/run/openvpn-server/not-openvpn.sock"
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: ([path], []))
    monkeypatch.setattr(
        openvpn, "_connect", lambda _p, _d: FakeSocket(initial=b"hello there\n")
    )
    available, reason = openvpn.probe_management_access()
    assert available is False
    assert "not an OpenVPN management socket" in reason


def test_probe_stops_at_the_instance_cap(monkeypatch):
    """The probe reads the same bounded set the collector does.

    It answers one boolean, and it runs on the collection loop (5-minute full
    probe plus the enabled-but-missing gap re-probe), so it must not walk an
    unbounded socket list to get there.
    """
    monkeypatch.setattr(openvpn, "_MAX_INSTANCES", 2)
    paths = [f"/run/openvpn-server/i{i}.sock" for i in range(4)]
    tried = []

    def connect(path, _deadline):
        tried.append(path)
        raise openvpn._InstanceError("connect failed: Permission denied")

    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: (paths, []))
    monkeypatch.setattr(openvpn, "_connect", connect)
    available, _reason = openvpn.probe_management_access()
    assert available is False
    assert tried == paths[:2]


def test_probe_closes_a_socket_that_never_greets(monkeypatch):
    """The refusal path is the one that repeats forever.

    A host with the wrong management-client-group is re-probed on every gap
    cycle for the life of the process; leaking the connection there would leak a
    descriptor per socket per probe on exactly the host that never answers.
    """
    sock = FakeSocket(initial=b"")
    monkeypatch.setattr(
        openvpn, "_discover_sockets", lambda: (["/run/openvpn/x.sock"], [])
    )
    monkeypatch.setattr(openvpn, "_connect", lambda _p, _d: sock)
    assert openvpn.probe_management_access()[0] is False
    assert sock.closed is True


# --- real unix socket ------------------------------------------------------


@pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="AF_UNIX is unavailable on Windows"
)
def test_end_to_end_over_a_real_unix_socket(monkeypatch):
    """The one test that exercises the actual transport rather than a stand-in:
    a real AF_UNIX server replaying a real OpenVPN 2.6.14 conversation.

    Deliberately NOT pytest's tmp_path: an AF_UNIX path is capped at ~104 bytes
    on macOS and pytest's per-test directory names blow straight past it.
    """
    directory = tempfile.mkdtemp()
    path = f"{directory}/server.sock"
    answers = {
        b"version": VERSION_ANSWER.encode(),
        b"status 3": _server_status(_client_row(since=900), time_t=998).encode(),
    }
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(1)

    def serve():
        conn, _ = listener.accept()
        conn.sendall(GREETING)
        buf = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip() == b"quit":
                    conn.close()
                    return
                conn.sendall(answers[line.strip()])

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        monkeypatch.setattr(openvpn.time, "time", lambda: 1000)
        monkeypatch.setattr(openvpn, "RUNTIME_DIRS", (directory,))
        result = openvpn.openvpn_metrics()
    finally:
        listener.close()
        thread.join(timeout=5)
        shutil.rmtree(directory, ignore_errors=True)

    assert result["instances"] == [
        {
            "name": "server",
            "socket": path,
            "mode": "server",
            "version": "OpenVPN 2.6.14",
            "status_age_s": 2,
            "clients": [
                {
                    "common_name": "site-lyon",
                    "identity_source": "cn",
                    "real_address": "203.0.113.5:51820",
                    "virtual_address": "10.8.0.6",
                    "username": "",
                    "sessions": 1,
                    "connected_age_s": 100,
                    "bytes_received": 1234,
                    "bytes_sent": 5678,
                    "cipher": "AES-256-GCM",
                }
            ],
            "state": None,
        }
    ]


def test_probe_is_bounded_by_a_wall_clock_budget(monkeypatch):
    """The probe needs its OWN budget, not just a per-socket timeout.

    It runs inside PermissionProbe, which has no timeout wrapper, on the same
    watchdog-bounded loop as collection. Per-socket-only bounding costs
    _SOCKET_TIMEOUT x _MAX_INSTANCES (64 x 5s = 320s), past WatchdogSec=90.
    """
    # AF_UNIX is injected rather than relied on: this exercises _connect's real
    # spent-budget bail, and on Windows (where the full suite runs in CI) the
    # absent-AF_UNIX guard would fire first and the budget path would never run.
    monkeypatch.setattr(openvpn.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(
        openvpn.socket, "socket", lambda *_a, **_k: pytest.fail("must not connect")
    )
    monkeypatch.setattr(openvpn, "_PROBE_DEADLINE", -1)
    paths = [f"/run/openvpn-server/i{i}.sock" for i in range(5)]
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: (paths, []))
    attempted = []
    real_connect = openvpn._connect

    def connect(path, deadline):
        attempted.append(path)
        return real_connect(path, deadline)

    monkeypatch.setattr(openvpn, "_connect", connect)
    available, reason = openvpn.probe_management_access()
    assert available is False
    # Every socket is still ATTEMPTED (the budget bounds work, not coverage),
    # but each gives up immediately instead of burning _PROBE_SOCKET_TIMEOUT --
    # the socket is never even opened, which the stub above asserts.
    assert len(attempted) == len(paths)
    assert "timed out" in reason


def test_probe_budget_is_shared_across_sockets(monkeypatch):
    """The deadline is a single budget for the loop, not a fresh one per socket."""
    monkeypatch.setattr(openvpn, "_PROBE_DEADLINE", 30)
    monkeypatch.setattr(openvpn, "_SOCKET_TIMEOUT", 5)
    paths = [f"/run/openvpn-server/i{i}.sock" for i in range(3)]
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: (paths, []))
    deadlines = []

    def connect(path, deadline):
        deadlines.append(deadline)
        raise openvpn._InstanceError("connect failed: refused")

    monkeypatch.setattr(openvpn, "_connect", connect)
    openvpn.probe_management_access()
    # A per-socket-only budget would hand out three deadlines ~5s apart as the
    # loop advances; a shared one keeps them within the single window.
    assert max(deadlines) - min(deadlines) < 1


def test_a_status_header_without_common_name_errors_the_instance():
    """Never fold every session into one anonymous entry.

    `_cell` returns None when the daemon's HEADER has no such column. Defaulting
    that to "" would collapse every session on the instance into a single
    nameless client with summed bytes -- a silent under-report that reads as one
    healthy client, which is the vanish-prune direction.
    """
    header = STATUS_HEADER.replace("Common Name\t", "")
    answer = (
        "TIME\t2026-09-11 18:57:00\t998\n"
        + header
        + "CLIENT_LIST\t203.0.113.5:51820\t10.8.0.6\t\t1\t2\tx\t900\tUNDEF\t0\t0\tc\n"
        "END\n"
    )
    _mode, _age, rows = openvpn._parse_status(answer.splitlines(), 1000)
    with pytest.raises(openvpn._InstanceError) as excinfo:
        openvpn._collapse_clients(rows, 1000)
    assert "Common Name" in str(excinfo.value)


def test_missing_common_name_column_surfaces_as_a_per_instance_error(monkeypatch):
    """And it stays scoped to that instance, never a host-wide null."""
    header = STATUS_HEADER.replace("Common Name\t", "")
    answer = (
        "TIME\t2026-09-11 18:57:00\t998\n"
        + header
        + "CLIENT_LIST\t203.0.113.5:51820\t10.8.0.6\t\t1\t2\tx\t900\tUNDEF\t0\t0\tc\n"
        "END\n"
    )
    path = "/run/openvpn-server/odd.sock"
    sock = FakeSocket(answers={"version": VERSION_ANSWER, "status 3": answer})
    result = _collect(monkeypatch, [path], {path: sock})
    assert result is not None
    assert "Common Name" in result["instances"][0]["error"]
    assert "clients" not in result["instances"][0]


def test_a_malformed_row_aborts_the_whole_read_never_skips_just_that_row():
    """The good row comes AFTER the bad one, on purpose.

    A parser that `continue`s past a row it cannot read ships a SHORT client
    list, and the server reads a non-empty list as the complete set -- so every
    dropped session is vanish-pruned. With the good row last, a skipping
    implementation returns `[the good row]` and this test fails; an aborting one
    raises. A single-bad-row fixture cannot tell those two apart.
    """
    answer = _server_status(
        "CLIENT_LIST\tsite-lyon\t203.0.113.5:51820\n" + _client_row(cn="site-paris")
    )
    with pytest.raises(openvpn._InstanceError):
        openvpn._parse_status(answer.splitlines(), 1000)


def test_a_missing_common_name_column_aborts_rather_than_dropping_rows():
    """Same shape for the collapse boundary: a readable row after an unreadable
    one must not be returned alone."""
    rows = [{"Real Address": "203.0.113.5:1"}, {"Common Name": "site-paris"}]
    with pytest.raises(openvpn._InstanceError):
        openvpn._collapse_clients(rows, 1000)


# --- pinned constants and bounds -------------------------------------------


def test_runtime_dirs_are_pinned_to_the_three_conventional_paths():
    """A LITERAL pin, never one derived from the constant under test.

    test_discover_sockets_uses_forward_slashes builds its expectation out of
    RUNTIME_DIRS itself, so shrinking the tuple satisfies it. Losing
    /run/openvpn-client on a host that ALSO runs a server instance is the bad
    shape: the client instance stops appearing in a NON-EMPTY instances array,
    which the server reads as the complete set and vanish-prunes -- the
    process-scan escape hatch never fires, because a socket was still found.
    """
    assert openvpn.RUNTIME_DIRS == (
        "/run/openvpn-server",
        "/run/openvpn",
        "/run/openvpn-client",
    )


def test_the_field_ceiling_is_pinned_to_a_literal():
    """Every bound assertion in this file measures against _MAX_FIELD_CHARS, so
    none of them can notice the ceiling itself moving."""
    assert openvpn._MAX_FIELD_CHARS == 200


def test_every_string_copied_out_of_the_daemon_is_bounded():
    """_cell is not the only door into the payload.

    test_cell_bounds_an_absurd_value pins the ceiling on CLIENT_LIST cells, but
    an instance's `error` and the whole state block come through _short, _pick
    and _remote instead -- all daemon-controlled, and one line may be as wide as
    _MAX_RESPONSE_BYTES. Dropping the slice from any of those passes every other
    test in this file.
    """
    huge = "y" * (openvpn._MAX_FIELD_CHARS * 5)
    assert len(openvpn._short(huge)) == openvpn._MAX_FIELD_CHARS
    assert len(openvpn._pick([huge], 0)) == openvpn._MAX_FIELD_CHARS
    assert len(openvpn._remote(huge, "1194")) == openvpn._MAX_FIELD_CHARS
    assert len(openvpn._instance_name(f"/run/openvpn-server/{huge}.sock")) == (
        openvpn._MAX_FIELD_CHARS
    )
    assert openvpn._short("  padded  ") == "padded"


def test_an_absurd_state_block_is_bounded_in_the_payload(monkeypatch):
    """End to end, because the state fields are the widest daemon-controlled
    strings that reach the server."""
    huge = "Z" * 5000
    path = "/run/openvpn-client/office.sock"
    sock = FakeSocket(
        answers={
            "version": VERSION_ANSWER,
            "status 3": CLIENT_STATUS + "END\n",
            "state": f"1000,{huge},{huge},{huge},{huge},1194,,\nEND\n",
        }
    )
    state = _collect(monkeypatch, [path], {path: sock})["instances"][0]["state"]
    for key in ("name", "description", "local_ip", "remote"):
        assert len(state[key]) == openvpn._MAX_FIELD_CHARS


def test_an_absurd_error_reason_is_bounded_in_the_payload(monkeypatch):
    """The error string is the one field an operator-facing failure path writes,
    and a wedged daemon can make it arbitrarily wide."""
    path = "/run/openvpn-server/server.sock"

    def connect(_path, _deadline):
        raise openvpn._InstanceError("E" * 5000)

    monkeypatch.setattr(openvpn.time, "time", lambda: 1000)
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: ([path], []))
    monkeypatch.setattr(openvpn, "_connect", connect)
    entry = openvpn.openvpn_metrics()["instances"][0]
    assert len(entry["error"]) == openvpn._MAX_FIELD_CHARS


# --- mode discrimination ----------------------------------------------------


def test_a_routing_table_header_alone_does_not_make_an_instance_a_server():
    """HEADER is a FAMILY, and only its CLIENT_LIST member identifies a server.

    Nothing else in this file varies the HEADER subtype, so a parser that
    accepted any HEADER line would pass the whole suite -- and would then report
    an answer whose only HEADER is the ROUTING_TABLE one as a server with zero
    clients, which is the false all-clear rather than an errored instance.
    """
    answer = [
        "TIME\t2026-09-11 18:57:00\t998",
        "HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address",
        "ROUTING_TABLE\t10.8.0.6\tsite-lyon\t203.0.113.5:51820",
    ]
    with pytest.raises(openvpn._InstanceError) as excinfo:
        openvpn._parse_status(answer, 1000)
    assert "unrecognized" in str(excinfo.value)


def test_a_client_banner_never_discards_an_already_parsed_client_list():
    """The two mode branches are ORDERED, and only one order is safe.

    Returning client first would answer ('client', []) for an answer that also
    carried a CLIENT_LIST, silently dropping every session already parsed -- the
    vanish-prune direction. Nothing else pins which branch wins.
    """
    answer = ("OpenVPN STATISTICS\n" + _server_status(_client_row())).splitlines()
    mode, _age, rows = openvpn._parse_status(answer, 1000)
    assert (mode, len(rows)) == ("server", 1)


def test_the_watchdog_budgets_are_pinned_and_fit_under_watchdogsec():
    """Every test that exercises a budget monkeypatches it, so nothing here
    notices the SHIPPED values moving.

    Both budgets can land on the SAME tick -- the capability probe runs on the
    collection loop (the 5-minute full probe, plus the enabled-but-missing gap
    re-probe) -- and fivenines-agent.service sets WatchdogSec=90. The module
    docstring does this arithmetic; nothing enforced it.
    """
    assert openvpn._SOCKET_TIMEOUT == 5
    assert openvpn._COLLECT_DEADLINE == 25
    assert openvpn._PROBE_SOCKET_TIMEOUT == 2
    assert openvpn._PROBE_DEADLINE == 10
    # The probe budget must cover MORE than one socket, or a single stalled
    # socket sorting first spends it all and the capability reports unavailable
    # on a host whose other instances answer fine.
    assert openvpn._PROBE_DEADLINE >= 2 * openvpn._PROBE_SOCKET_TIMEOUT
    assert openvpn._PROBE_SOCKET_TIMEOUT <= openvpn._SOCKET_TIMEOUT
    assert openvpn._PROBE_DEADLINE <= openvpn._COLLECT_DEADLINE
    assert openvpn._COLLECT_DEADLINE + openvpn._PROBE_DEADLINE < 90


def test_the_instance_and_response_bounds_are_pinned():
    """_MAX_INSTANCES bounds the whole tick, _MAX_RESPONSE_BYTES bounds one
    instance's read into memory. Both exist only as monkeypatched stand-ins
    everywhere else in this file."""
    assert openvpn._MAX_INSTANCES == 64
    assert openvpn._MAX_RESPONSE_BYTES == 8 * 1024 * 1024


def test_the_version_banner_is_bounded_too():
    """The trim to two tokens is not a length bound: a daemon reporting one
    absurd token would ship it whole."""
    banner = "z" * (openvpn._MAX_FIELD_CHARS * 4)
    version = openvpn._parse_version([f"OpenVPN Version: {banner}"])
    assert len(version) == openvpn._MAX_FIELD_CHARS


# --- probe discrimination and reason selection -----------------------------


def test_only_the_info_greeting_proves_authorization(monkeypatch):
    """A NEAR-MISS negative, because the far-away one ('hello there') also
    passes a discriminator loosened to any '>' line.

    Every management notification is '>'-prefixed, but only '>INFO:' is written
    at accept(): it is the one line whose arrival proves the daemon did not drop
    us on the management-client-group check.
    """
    path = "/run/openvpn-server/server.sock"
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: ([path], []))
    monkeypatch.setattr(
        openvpn,
        "_connect",
        lambda _p, _d: FakeSocket(initial=b">CLIENT:ESTABLISHED,0\n"),
    )
    available, reason = openvpn.probe_management_access()
    assert available is False
    assert "not an OpenVPN management socket" in reason


def test_probe_keeps_the_first_reason_when_every_socket_refuses(monkeypatch):
    """test_probe_reports_the_first_failure_when_none_answer only exercises the
    CONNECT branch; the greeting branch keeps the first reason as well.

    The reason exists to name a socket the operator can go and look at, and on
    a host whose management-client-group is wrong EVERY socket refuses -- so
    which one is named is the whole content of the message.
    """
    first = "/run/openvpn-server/a.sock"
    second = "/run/openvpn-server/b.sock"
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: ([first, second], []))
    monkeypatch.setattr(openvpn, "_connect", lambda _p, _d: FakeSocket(initial=b""))
    available, reason = openvpn.probe_management_access()
    assert available is False
    assert reason.startswith(f"{first}: ")


def test_probe_keeps_the_first_reason_when_no_socket_is_openvpn(monkeypatch):
    """Same rule on the third reason branch."""
    first = "/run/openvpn-server/a.sock"
    second = "/run/openvpn-server/b.sock"
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: ([first, second], []))
    monkeypatch.setattr(
        openvpn, "_connect", lambda _p, _d: FakeSocket(initial=b"hello there\n")
    )
    available, reason = openvpn.probe_management_access()
    assert available is False
    assert reason.startswith(f"{first}: ")


@_needs_posix_permissions
def test_an_unreadable_runtime_directory_is_blind_not_empty(tmp_path, monkeypatch):
    """glob.glob swallows EACCES and returns [], which is the SAME answer it
    gives for a host with no OpenVPN -- and that answer is the prune-all.

    This is the measured RHEL case: the openvpn RPM ships /run/openvpn-server as
    0750 root:openvpn, so an agent outside that group cannot traverse it.
    """
    blind = tmp_path / "run-openvpn-server"
    blind.mkdir()
    blind.chmod(0o000)
    monkeypatch.setattr(openvpn, "RUNTIME_DIRS", (str(blind),))
    try:
        # The bare glob really does come back empty rather than raising -- which
        # is exactly why the explicit readability check has to exist.
        assert openvpn.glob.glob(f"{blind}/*.sock") == []
        with pytest.raises(openvpn._DiscoveryError):
            openvpn._discover_sockets()
        # ...and the collector turns that into null, never {"instances": []}.
        monkeypatch.setattr(openvpn, "_openvpn_is_running", lambda: False)
        assert openvpn.openvpn_metrics() is None
    finally:
        blind.chmod(0o755)


def test_a_missing_runtime_directory_is_not_an_error(tmp_path, monkeypatch):
    """Absent is genuinely empty -- only UNREADABLE is blind."""
    monkeypatch.setattr(openvpn, "RUNTIME_DIRS", (str(tmp_path / "nope"),))
    assert openvpn._discover_sockets() == ([], [])


def test_discovery_skips_entries_that_are_not_sockets(tmp_path, monkeypatch):
    """A lock file or a dangling symlink matching the glob must never be dialled."""
    monkeypatch.setattr(openvpn, "RUNTIME_DIRS", (str(tmp_path),))
    (tmp_path / "regular.sock").write_text("not a socket")
    (tmp_path / "dangling.sock").symlink_to(tmp_path / "gone")
    assert openvpn._discover_sockets() == ([], [])


@pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="AF_UNIX is unavailable on Windows"
)
def test_discovery_accepts_a_real_socket(monkeypatch):
    directory = tempfile.mkdtemp()
    path = f"{directory}/server.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    try:
        monkeypatch.setattr(openvpn, "RUNTIME_DIRS", (directory,))
        assert openvpn._discover_sockets() == ([path], [])
    finally:
        listener.close()
        shutil.rmtree(directory, ignore_errors=True)


@pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="AF_UNIX is unavailable on Windows"
)
def test_discovery_accepts_a_symlink_to_a_real_socket(monkeypatch):
    """The case the realpath dedup exists for must survive the S_ISSOCK check.

    An operator symlinking one instance's socket into a second runtime
    directory (or /var/run being a symlink to /run) is the whole reason
    _discover_sockets de-duplicates by realpath. os.stat follows symlinks, so
    the link is a socket too -- an lstat here would skip it and silently drop
    the instance from an array the server reads as the complete set.
    """
    directory = tempfile.mkdtemp()
    real = f"{directory}/a-real.sock"
    link = f"{directory}/z-link.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(real)
    os.symlink(real, link)
    try:
        monkeypatch.setattr(openvpn, "RUNTIME_DIRS", (directory,))
        assert openvpn._is_socket(link) is True
        # Both names resolve to one socket, so exactly one instance is read.
        assert openvpn._discover_sockets() == ([real], [])
    finally:
        listener.close()
        shutil.rmtree(directory, ignore_errors=True)


def test_a_slow_instance_does_not_starve_the_tail_forever(monkeypatch):
    """One shared budget + a fixed start = a PERMANENT blind spot.

    The starved instances ship an `error` every tick, which the server reads as
    a per-instance null and FREEZES -- so a healthy VPN behind a wedged one
    never reports again and its open incidents never resolve. Rotation is the
    same fix agent._rotated_ping_targets applies to the ping map.
    """
    slow = [f"/run/openvpn-server/a{i}.sock" for i in range(3)]
    healthy = ["/run/openvpn-server/z0.sock"]
    paths = slow + healthy

    def connect(path, _deadline):
        if path in slow:
            # Accepts, then never speaks -- burns the whole per-socket timeout.
            return FakeSocket(initial=b"", recv_error=socket.timeout("timed out"))
        return FakeSocket(
            answers={"version": VERSION_ANSWER, "status 3": _server_status()}
        )

    monkeypatch.setattr(openvpn.time, "time", lambda: 1000)
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: (list(paths), []))
    monkeypatch.setattr(openvpn, "_connect", connect)
    # A budget that only affords one instance per tick.
    monkeypatch.setattr(openvpn, "_COLLECT_DEADLINE", 0.001)

    read_ok = set()
    for _ in range(len(paths)):
        for entry in openvpn.openvpn_metrics()["instances"]:
            if "clients" in entry:
                read_ok.add(entry["name"])
    assert "z0" in read_ok, "the tail instance was never reached across a full cycle"


def test_the_payload_order_stays_stable_while_reads_rotate(monkeypatch):
    """Rotation must change which instances are READ, never the array's shape."""
    paths = [f"/run/openvpn-server/i{i}.sock" for i in range(3)]
    monkeypatch.setattr(openvpn.time, "time", lambda: 1000)
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: (list(paths), []))
    monkeypatch.setattr(
        openvpn,
        "_connect",
        lambda _p, _d: FakeSocket(
            answers={"version": VERSION_ANSWER, "status 3": _server_status()}
        ),
    )
    first = [i["socket"] for i in openvpn.openvpn_metrics()["instances"]]
    second = [i["socket"] for i in openvpn.openvpn_metrics()["instances"]]
    assert first == second == paths


def test_the_rotation_advances_every_tick(monkeypatch):
    seen = []
    paths = ["/run/openvpn-server/a.sock", "/run/openvpn-server/b.sock"]
    monkeypatch.setattr(openvpn.time, "time", lambda: 1000)
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: (list(paths), []))

    def connect(path, _deadline):
        seen.append(path)
        raise openvpn._InstanceError("refused")

    monkeypatch.setattr(openvpn, "_connect", connect)
    openvpn.openvpn_metrics()
    openvpn.openvpn_metrics()
    # Tick 1 starts at a, tick 2 starts at b.
    assert seen == [paths[0], paths[1], paths[1], paths[0]]


def test_the_process_scan_is_cached(monkeypatch):
    """A full process walk every tick, forever, to learn the same constant."""
    calls = []

    def process_iter(_attrs):
        calls.append(1)
        return [_FakeProcess("sshd")]

    monkeypatch.setattr(openvpn.psutil, "process_iter", process_iter)
    assert openvpn._openvpn_is_running() is False
    assert openvpn._openvpn_is_running() is False
    assert len(calls) == 1, "the answer should be reused within the TTL"


def test_the_process_scan_cache_expires(monkeypatch):
    calls = []

    def process_iter(_attrs):
        calls.append(1)
        return [_FakeProcess("sshd")]

    monkeypatch.setattr(openvpn.psutil, "process_iter", process_iter)
    assert openvpn._openvpn_is_running() is False
    monkeypatch.setattr(openvpn, "_PROCESS_SCAN_TTL", -1)
    assert openvpn._openvpn_is_running() is False
    assert len(calls) == 2


def test_the_process_scan_stops_at_the_first_match(monkeypatch):
    """A match must not walk the rest of the process table."""
    walked = []

    class _Counting:
        def __init__(self, names):
            self._names = names

        def __iter__(self):
            for n in self._names:
                walked.append(n)
                yield _FakeProcess(n)

    monkeypatch.setattr(
        openvpn.psutil, "process_iter", lambda _a: _Counting(["openvpn", "sshd"])
    )
    assert openvpn._openvpn_is_running() is True
    assert walked == ["openvpn"]


def test_an_ipv6_remote_is_bracketed_so_host_and_port_survive():
    """`2001:db8::1:1194` is unrecoverable; `[2001:db8::1]:1194` is not.

    It also matches how OpenVPN itself writes real_address, so one payload does
    not carry two encodings of the same concept.
    """
    parsed = openvpn._parse_state(
        ["1000,CONNECTED,SUCCESS,10.8.0.2,2001:db8::1,1194,,"], 1000
    )
    assert parsed["remote"] == "[2001:db8::1]:1194"


def test_an_ipv4_remote_is_not_bracketed():
    parsed = openvpn._parse_state(
        ["1000,CONNECTED,SUCCESS,10.8.0.2,198.51.100.7,1194,,"], 1000
    )
    assert parsed["remote"] == "198.51.100.7:1194"


def _undef_cn_rows():
    """Three sessions on a --verify-client-cert none server.

    OpenVPN writes its UNDEF sentinel into the Common Name column for every
    session and puts the real identity in Username.
    """
    return _rows(
        _client_row(
            cn="UNDEF", user="alice", real="203.0.113.5:1", rx=100, tx=200, since=99000
        ),
        _client_row(
            cn="UNDEF", user="bob", real="198.51.100.9:2", rx=300, tx=400, since=99000
        ),
        _client_row(
            cn="UNDEF", user="carol", real="198.51.100.9:3", rx=500, tx=600, since=99000
        ),
    )


def test_undef_common_names_do_not_fold_into_one_anonymous_client():
    """The bug three specialists confirmed and one reproduced.

    Keying on the CN alone gives every session the same key on a username-auth
    server, so all of them collapse into one entry with summed bytes -- and
    because the server reads a non-empty `clients` array as the COMPLETE set,
    every other client row on that instance is pruned on every tick.
    """
    clients = openvpn._collapse_clients(_undef_cn_rows(), 100000)
    assert len(clients) == 3
    assert {c["common_name"] for c in clients} == {"alice", "bob", "carol"}
    # Not folded: each keeps its own counters rather than one summed row.
    assert sorted(c["bytes_received"] for c in clients) == [100, 300, 500]


def test_a_real_common_name_still_wins_over_the_username():
    """Username is the FALLBACK, never an override -- certificate CN is the
    durable identity when the daemon reports one."""
    clients = openvpn._collapse_clients(
        _rows(_client_row(cn="site-lyon", user="alice")), 100000
    )
    assert clients[0]["common_name"] == "site-lyon"
    assert clients[0]["username"] == "alice"


def test_duplicate_cn_still_collapses_under_the_username_fallback():
    """The fallback must not break the rule it shares a function with: two
    sessions for the SAME username still collapse."""
    clients = openvpn._collapse_clients(
        _rows(
            _client_row(cn="UNDEF", user="alice", rx=100, tx=200, since=99880),
            _client_row(cn="UNDEF", user="alice", rx=300, tx=400, since=13600),
        ),
        100000,
    )
    assert len(clients) == 1
    assert clients[0]["common_name"] == "alice"
    assert clients[0]["sessions"] == 2
    assert (clients[0]["bytes_received"], clients[0]["bytes_sent"]) == (400, 600)
    assert clients[0]["connected_age_s"] == 86400


def test_a_row_with_no_identity_at_all_errors_the_instance():
    """Neither column carries an identity -- genuinely ambiguous, so refuse the
    instance rather than guess. Never fall back to a shared empty key."""
    with pytest.raises(openvpn._InstanceError) as excinfo:
        openvpn._collapse_clients(_rows(_client_row(cn="UNDEF", user="UNDEF")), 100000)
    assert "no identity" in str(excinfo.value)


def test_an_undef_identity_row_aborts_rather_than_dropping_later_rows():
    """Trailing-good-row shape: a skipping implementation would return the
    identified row alone and silently prune the rest."""
    rows = _rows(
        _client_row(cn="UNDEF", user="UNDEF"),
        _client_row(cn="site-paris", user="UNDEF"),
    )
    with pytest.raises(openvpn._InstanceError):
        openvpn._collapse_clients(rows, 100000)


def test_rotating_an_empty_list_is_a_no_op():
    """Guard the modulo: `_rotation % 0` would be a ZeroDivisionError, and the
    empty case is reachable whenever discovery comes up dry."""
    assert openvpn._rotated([]) == []


@_needs_posix_permissions
def test_an_unreadable_directory_does_not_discard_sockets_from_the_others(
    tmp_path, monkeypatch
):
    """Aborting discovery on the first blind directory throws away a real
    reading -- and on Debian that is the NORMAL layout, not an edge case:
    /run/openvpn-server ships 0710 root:root right next to the readable
    /run/openvpn that actually holds the operator's socket.
    """
    blind = tmp_path / "openvpn-server"
    blind.mkdir()
    readable = tmp_path / "openvpn"
    readable.mkdir()
    monkeypatch.setattr(openvpn, "RUNTIME_DIRS", (str(blind), str(readable)))
    monkeypatch.setattr(openvpn, "_is_socket", lambda _p: True)
    (readable / "site.sock").write_text("")
    blind.chmod(0o000)
    try:
        assert openvpn._discover_sockets() == ([f"{readable}/site.sock"], [str(blind)])
    finally:
        blind.chmod(0o755)


@_needs_posix_permissions
def test_every_directory_blind_and_nothing_found_is_still_a_failure(
    tmp_path, monkeypatch
):
    """Blind-vs-empty is only ambiguous when the result is EMPTY."""
    blind = tmp_path / "openvpn-server"
    blind.mkdir()
    blind.chmod(0o000)
    monkeypatch.setattr(openvpn, "RUNTIME_DIRS", (str(blind),))
    try:
        with pytest.raises(openvpn._DiscoveryError):
            openvpn._discover_sockets()
    finally:
        blind.chmod(0o755)


def test_a_path_we_cannot_stat_is_kept_not_dropped(monkeypatch):
    """EACCES is not evidence of absence.

    Dropping it would remove the instance from an array the server reads as the
    complete set -- pruning its rows. Keeping it means the instance is dialled
    and reported as a per-instance error instead: frozen, not deleted.
    """

    def boom(_path):
        raise PermissionError("Permission denied")

    monkeypatch.setattr(openvpn.os, "stat", boom)
    assert openvpn._is_socket("/run/openvpn/unreachable.sock") is True


def test_a_vanished_path_is_dropped(monkeypatch):
    def gone(_path):
        raise FileNotFoundError("no such file")

    monkeypatch.setattr(openvpn.os, "stat", gone)
    assert openvpn._is_socket("/run/openvpn/gone.sock") is False


def test_the_probe_budget_survives_one_stalled_socket(monkeypatch):
    """A stalled socket sorting first must not blind the whole probe."""
    stalled = "/run/openvpn-server/a-stalled.sock"
    healthy = "/run/openvpn-server/z-healthy.sock"
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: ([stalled, healthy], []))

    def connect(path, _deadline):
        if path == stalled:
            return FakeSocket(initial=b"", recv_error=socket.timeout("timed out"))
        return FakeSocket()

    monkeypatch.setattr(openvpn, "_connect", connect)
    assert openvpn.probe_management_access() == (True, None)


def test_the_rotation_survives_a_flapping_instance_count(monkeypatch):
    """Folding the cursor into the CURRENT count resets its phase whenever an
    instance appears or disappears, pinning a flapping host near index 0."""
    three = ["a", "b", "c"]
    two = ["a", "b"]
    starts = []
    for tick in range(6):
        paths = three if tick % 2 == 0 else two
        starts.append(openvpn._rotated(three)[0] if paths is three else None)
        if paths is two:
            openvpn._rotated(two)
    # Over three visits to the 3-path list every index must have led at least
    # once; a count-folded cursor never leaves 'a'.
    assert len({s for s in starts if s}) > 1


def test_a_username_never_folds_into_a_same_spelled_certificate_cn():
    """--verify-client-cert optional puts both kinds of session on one daemon.

    Merging them prunes the second real client and misreports the merged row as
    duplicate-cn.
    """
    clients = openvpn._collapse_clients(
        _rows(
            _client_row(cn="alice", user="UNDEF", rx=100, tx=200),
            _client_row(cn="UNDEF", user="alice", rx=300, tx=400),
        ),
        100000,
    )
    assert len(clients) == 2
    assert [c["common_name"] for c in clients] == ["alice", "alice"]
    assert sorted(c["bytes_received"] for c in clients) == [100, 300]


@_needs_posix_permissions
def test_a_blind_directory_is_reported_not_silently_dropped(tmp_path, monkeypatch):
    """Finding a socket elsewhere does not make an unreadable directory
    harmless: the instances inside it would vanish from an array the server
    reads as the complete set. A partially-blind tick must look incomplete.
    """
    blind = tmp_path / "openvpn-server"
    blind.mkdir()
    readable = tmp_path / "openvpn"
    readable.mkdir()
    path = f"{readable}/site.sock"
    monkeypatch.setattr(openvpn, "RUNTIME_DIRS", (str(blind), str(readable)))
    monkeypatch.setattr(openvpn, "_is_socket", lambda _p: True)
    (readable / "site.sock").write_text("")
    monkeypatch.setattr(openvpn.time, "time", lambda: 1000)
    monkeypatch.setattr(
        openvpn,
        "_connect",
        lambda _p, _d: FakeSocket(
            answers={"version": VERSION_ANSWER, "status 3": _server_status()}
        ),
    )
    blind.chmod(0o000)
    try:
        result = openvpn.openvpn_metrics()
    finally:
        blind.chmod(0o755)

    assert [i["socket"] for i in result["instances"]] == [path, str(blind)]
    blind_entry = result["instances"][1]
    assert blind_entry["error"] == "runtime directory not readable"
    # A per-instance null: no clients key, so the server freezes rather than
    # concluding the instances inside were removed.
    assert "clients" not in blind_entry


@_needs_posix_permissions
def test_a_blind_directory_is_reported_at_error_level(tmp_path, monkeypatch):
    """The default log level is info, so a debug line would never reach the
    operator whose action is required."""
    blind = tmp_path / "openvpn-server"
    blind.mkdir()
    readable = tmp_path / "openvpn"
    readable.mkdir()
    (readable / "site.sock").write_text("")
    monkeypatch.setattr(openvpn, "RUNTIME_DIRS", (str(blind), str(readable)))
    monkeypatch.setattr(openvpn, "_is_socket", lambda _p: True)
    monkeypatch.setattr(openvpn.time, "time", lambda: 1000)
    monkeypatch.setattr(openvpn, "_connect", lambda _p, _d: FakeSocket(initial=b""))
    levels = []
    monkeypatch.setattr(openvpn, "log", lambda msg, level: levels.append((level, msg)))
    blind.chmod(0o000)
    try:
        openvpn.openvpn_metrics()
    finally:
        blind.chmod(0o755)
    assert any(level == "error" and "not readable" in msg for level, msg in levels)


@_needs_posix_permissions
def test_the_probe_names_an_unreadable_directory(tmp_path, monkeypatch):
    blind = tmp_path / "openvpn-server"
    blind.mkdir()
    empty = tmp_path / "openvpn"
    empty.mkdir()
    monkeypatch.setattr(openvpn, "RUNTIME_DIRS", (str(blind), str(empty)))
    blind.chmod(0o000)
    try:
        available, reason = openvpn.probe_management_access()
    finally:
        blind.chmod(0o755)
    assert available is False
    # Blind AND nothing found anywhere is a discovery failure, not a "no socket
    # here" answer -- the probe must say so rather than report a clean absence.
    assert "could not list the runtime directories" in reason
    assert "not readable" in reason
