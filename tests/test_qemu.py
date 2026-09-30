"""Tests for fivenines_agent.qemu module.

The libvirt URI allowlist (agent #142) is the focus: a libvirt URI selects a
transport, and `ext` / `ssh` / `tcp` transports execute a local command or
dial out regardless of openReadOnly(), so the collector must refuse to open
anything but the local hypervisor socket -- with NO libvirt call on refusal
and a None payload (collection failure) rather than [] (zero VMs).

The collection time bounds (agent #171) are the other: no libvirt call carries
a timeout, so the collection runs on a single-flight worker the tick stops
waiting for (COLLECT_TIMEOUT) and stops calling libvirt once its budget is
spent (COLLECT_BUDGET) -- None in both cases, never a partial VM list.
"""

import contextlib
import os
import re
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import psutil
import pytest

import fivenines_agent.qemu as qemu
from fivenines_agent.collectors import collect_metrics
from fivenines_agent.qemu import QEMUCollector, libvirt_uri_rejection, qemu_metrics

# The log-once register (qemu._last_refused_uri) is module-level state; the
# autouse fixture in tests/conftest.py resets it before every test.


@pytest.fixture(autouse=True)
def _no_host_processes():
    """Keep the VM uptime scan off the host's real process table: the tests
    stay deterministic, and a full cmdline scan is slow on a Windows runner.
    The uptime tests patch in their own processes."""
    with patch.object(qemu.psutil, "pids", return_value=[]), patch.object(
        qemu.psutil,
        "process_iter",
        side_effect=AssertionError("the uptime scan must not use psutil's cache"),
    ):
        yield


# The real functions, for the one test that scans real processes.
_REAL_PIDS = psutil.pids
_REAL_PROCESS = psutil.Process


# fake_libvirt (a libvirt double installed as fivenines_agent.qemu.libvirt)
# comes from tests/conftest.py.


def _refuse_twice(uri):
    """Construct a collector for *uri* twice under a mocked log -- the
    error-level first refusal AND the debug-level repeat are both channels
    that can reach the journal -- and return (collector, mock_log)."""
    with patch("fivenines_agent.qemu.log") as mock_log:
        collector = QEMUCollector(uri)
        QEMUCollector(uri)
    return collector, mock_log


# --- libvirt_uri_rejection: the allowlist ---


@pytest.mark.parametrize(
    "uri",
    [
        "qemu:///system",
        "qemu:///session",
        "qemu+unix:///system",
        "qemu+unix:///session",
        "qemu+unix:///system?socket=/var/run/libvirt/libvirt-sock",
        "qemu+unix:///system?socket=/run/libvirt/virtqemud-sock&mode=direct",
        "qemu:///system?mode=legacy",
        "qemu+unix:///session?mode=auto",
        "qemu:///system?",
    ],
)
def test_allowlist_accepts_local_socket_uris(uri):
    assert libvirt_uri_rejection(uri) is None


@pytest.mark.parametrize(
    "uri,fragment",
    [
        # exec-capable / remote transports
        ("qemu+ext:///system?command=/tmp/evil", "scheme 'qemu+ext'"),
        ("qemu+ssh://root@host/system", "scheme 'qemu+ssh'"),
        ("qemu+ssh://host/system?command=/tmp/evil", "scheme 'qemu+ssh'"),
        ("qemu+libssh://host/system", "scheme 'qemu+libssh'"),
        ("qemu+libssh2://host/system", "scheme 'qemu+libssh2'"),
        ("qemu+tcp://host/system", "scheme 'qemu+tcp'"),
        ("qemu+tls://host/system", "scheme 'qemu+tls'"),
        # a host with no explicit transport is an implicit TLS connection
        ("qemu://host/system", "authority component"),
        ("qemu://host:16509/system", "authority component"),
        ("qemu+unix://host/system", "authority component"),
        # other drivers, including the in-process ones
        ("test:///default", "scheme (unrecognized)"),
        ("xen:///system", "scheme (unrecognized)"),
        ("lxc:///", "scheme (unrecognized)"),
        ("qemu:///embed?root=/tmp/x", "path is not one of"),
        # not a hypervisor path
        ("qemu:///", "path is not one of"),
        ("qemu:///system/", "path is not one of"),
        ("qemu:///SYSTEM", "path is not one of"),
        ("qemu+unix:////system", "path is not one of"),
        # unix-transport parameters outside the two the transport reads
        ("qemu:///system?command=/tmp/x", "query parameter is not one of"),
        ("qemu+unix:///system?netcat=/tmp/x", "query parameter is not one of"),
        (
            "qemu+unix:///system?name=qemu+ssh://h/system",
            "query parameter is not one of",
        ),
        (
            "qemu+unix:///system?socket=/run/libvirt/a&proxy=native",
            "query parameter is not one of",
        ),
        ("qemu+unix:///system?socket=relative/path", "socket= is not a normalized"),
        ("qemu+unix:///system?socket=", "socket= is not a normalized"),
        ("qemu+unix:///system?socket", "socket= is not a normalized"),
        ("qemu+unix:///system?mode=evil", "mode= is not one of"),
        ("qemu:///system#frag", "fragment"),
        # scheme-less / non-URI values
        ("/var/run/libvirt/libvirt-sock", "scheme (none)"),
        ("system", "scheme (none)"),
        ("qemu://[::1/system", "does not parse"),
        # a ";" anywhere in the query is refused outright: libvirt treats it
        # as a separator only when no "&" remains, so the two parsers would
        # otherwise read a mixed query differently (mode=auto;mode=direct&...
        # is two valid modes to a naive splitter, one invalid mode to libvirt)
        ("qemu:///system?socket=/a;command=/b&mode=auto", "query contains ';'"),
        (
            "qemu:///system?mode=auto;mode=direct&socket=/run/libvirt/libvirt-sock",
            "query contains ';'",
        ),
        (
            "qemu:///system?socket=/run/libvirt/a;socket=/run/libvirt/b",
            "query contains ';'",
        ),
        # socket= must be a normalized path to a file inside a libvirt socket
        # directory: any other local socket could wedge the collection
        # worker for good (docker.sock reads and waits) or start a
        # socket-activated service
        ("qemu+unix:///system?socket=/run/docker.sock", "socket= is not a normalized"),
        ("qemu+unix:///system?socket=/run/snapd.socket", "socket= is not a normalized"),
        ("qemu+unix:///system?socket=/tmp/libvirt-sock", "socket= is not a normalized"),
        (
            "qemu+unix:///system?socket=/run/libvirt/../docker.sock",
            "socket= is not a normalized",
        ),
        ("qemu+unix:///system?socket=/run/libvirt//x", "socket= is not a normalized"),
        ("qemu+unix:///system?socket=/run/libvirt/./x", "socket= is not a normalized"),
        ("qemu+unix:///system?socket=/run/libvirt/", "socket= is not a normalized"),
        ("qemu+unix:///system?socket=/run/libvirt", "socket= is not a normalized"),
        ("qemu+unix:///system?socket=/run/libvirtd/x", "socket= is not a normalized"),
        # the directory must PREFIX the path, not merely appear in it
        (
            "qemu+unix:///system?socket=/home/u/run/libvirt/evil.sock",
            "socket= is not a normalized",
        ),
        (
            "qemu+unix:///system?socket=/proc/1/root/run/libvirt/x",
            "socket= is not a normalized",
        ),
        # decoded values must be printable: libvirt decodes them too and its
        # connect error would echo a forged journal line or an escape sequence
        ("qemu+unix:///system?socket=/run/libvirt/%0aforged", "whitespace or control"),
        ("qemu+unix:///system?socket=/run/libvirt/%1b%5b2J", "whitespace or control"),
        ("qemu+unix:///system?socket=/run/libvirt/a%20b", "whitespace or control"),
        ("qemu:///system?mode=%0a", "whitespace or control"),
        # libvirt silently IGNORES a `=value` segment with no name; the agent
        # refuses it rather than guess
        ("qemu:///system?=x", "query parameter is not one of"),
        # the path is compared raw, never percent-decoded: a spelling libvirt
        # might normalise to /system is still refused here
        ("qemu:///%73ystem", "path is not one of"),
        # userinfo with no host is still an authority component
        ("qemu://@/system", "authority component"),
        # would defer to LIBVIRT_DEFAULT_URI / libvirt.conf
        ("", "non-empty string"),
        (None, "non-empty string"),
        (123, "non-empty string"),
        (["qemu:///system"], "non-empty string"),
    ],
)
def test_allowlist_refuses_everything_else(uri, fragment):
    reason = libvirt_uri_rejection(uri)
    assert reason is not None
    assert fragment in reason


@pytest.mark.parametrize(
    "uri",
    [
        "qemu:///system\n",
        "qemu:///sys tem",
        "qemu+\tunix:///system",
        "qemu:///system\x00",
    ],
)
def test_allowlist_refuses_whitespace_and_control_characters(uri):
    """urlsplit strips tabs/newlines before parsing, so a raw string libvirt
    would see differently must be refused on the raw form, not the parsed."""
    assert "whitespace or control" in libvirt_uri_rejection(uri)


def test_allowlist_refuses_any_semicolon_in_the_query():
    """libvirt's virURIParseParams treats ';' as a separator only when no
    '&' remains; rather than emulate that fallback, any ';' is refused so an
    accepted query is parsed identically by both."""
    for query in ("socket=/a;command=/b", "mode=auto;x", ";", "mode=auto&x;y"):
        assert "query contains ';'" in libvirt_uri_rejection("qemu:///system?" + query)


def test_socket_path_accepts_session_dir_only_when_xdg_runtime_dir_is_set(monkeypatch):
    uri = "qemu+unix:///session?socket=/run/user/1000/libvirt/virtqemud-sock"
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert "socket= is not a normalized" in libvirt_uri_rejection(uri)
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    assert libvirt_uri_rejection(uri) is None
    # the variable itself must be a normalized absolute path to count
    for bad in ("run/user/1000", "/run/user/1000/", "/run/user/../1000", ""):
        monkeypatch.setenv("XDG_RUNTIME_DIR", bad)
        assert "socket= is not a normalized" in libvirt_uri_rejection(uri)


@pytest.mark.parametrize(
    "socket_path",
    [
        # the rootless Docker socket the agent itself builds from
        # XDG_RUNTIME_DIR -- exactly the "reads and waits" stall target
        "/run/user/1000/docker.sock",
        "/run/user/1000/podman/podman.sock",
        # the appended segment is "/libvirt/", not a prefix of it
        "/run/user/1000/libvirt-evil/x",
        "/run/user/1000/libvirtd",
        "/run/user/1000/libvirt",
    ],
)
def test_xdg_session_dir_admits_only_its_libvirt_subdirectory(monkeypatch, socket_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    reason = libvirt_uri_rejection(f"qemu+unix:///session?socket={socket_path}")
    assert "socket= is not a normalized" in reason


def test_socket_paths_are_posix_whatever_the_host_os(monkeypatch):
    """A libvirt unix socket path is always POSIX. Normalizing with os.path
    would be ntpath on Windows and refuse every legitimate path there (the
    cgroup.py precedent), so the check must not depend on the host OS."""
    import ntpath

    monkeypatch.setattr(qemu.os, "path", ntpath)
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    assert (
        libvirt_uri_rejection("qemu+unix:///system?socket=/run/libvirt/virtqemud-sock")
        is None
    )
    assert (
        libvirt_uri_rejection(
            "qemu+unix:///session?socket=/run/user/1000/libvirt/virtqemud-sock"
        )
        is None
    )


def test_allowlist_percent_decodes_parameter_names():
    reason = libvirt_uri_rejection("qemu:///system?%63ommand=/b")
    assert "query parameter is not one of" in reason


@pytest.mark.parametrize(
    "uri", ["QEMU:///system", "Qemu+unix:///session", "qemu+UNIX:///system"]
)
def test_allowlist_scheme_is_case_sensitive_like_libvirt(uri):
    """urlsplit lowercases the scheme, but libvirt matches the driver name
    case-sensitively (only the transport after "+" is folded), so the agent
    compares the raw spelling: it must accept no spelling libvirt would not."""
    reason = libvirt_uri_rejection(uri)
    assert reason is not None
    assert f"scheme {uri.partition(':')[0]!r}" in reason


def test_refusal_log_and_reason_never_carry_credentials(fake_libvirt):
    """A hostile URI may embed a credential in its userinfo or a query value;
    neither the log line nor the rejection reason may echo it (the log line
    is captured into error telemetry and sent back to the backend)."""
    uri = "qemu+ssh://root:hunter2@hv1/system?keyfile=/root/.ssh/id_rsa"
    collector, mock_log = _refuse_twice(uri)
    for message in (call.args[0] for call in mock_log.call_args_list):
        assert "hunter2" not in message and "id_rsa" not in message
        assert "hv1" not in message  # the URI itself is never echoed
        assert message.startswith("Refusing configured libvirt URI: scheme 'qemu+ssh'")
    assert "hunter2" not in collector.refused
    reason = libvirt_uri_rejection("qemu://root:hunter2@hv1/system")
    assert "hunter2" not in reason and "hv1" not in reason
    assert "authority component" in reason


@pytest.mark.parametrize(
    "uri",
    [
        # malformed passwords: an unencoded "@", "/" or "?" in the userinfo
        "qemu+ssh://user:s3c@r3t@host/system",
        "qemu+ssh://user:s3c/r3t@host/system",
        "qemu+ssh://user:s3c?r3t@host/system",
        "qemu://user:s3c/r3t@host/system",
        # secrets in parameter values, on an otherwise local URI
        "qemu+unix:///system?socket=s3c/r3t",
        "qemu+unix:///system?mode=s3cr3t",
        "qemu:///system?token=s3cr3t",
        # secrets in a parameter NAME (bare, and percent-encoded)
        "qemu:///system?s3cr3t",
        "qemu:///system?s3c%2Fr3t=1",
        # a netloc urlsplit itself rejects (fullwidth colon, NFKC-invalid):
        # CPython's ValueError message embeds the RAW netloc, userinfo included
        "qemu+ssh://root:s3cr3t@hv1\uff1a22/system",
        "qemu+ssh://root\uff1as3cr3t@hv1/system",
        # an "@" inside a query value or fragment
        "qemu:///system?token=s3c@r3t",
        "qemu+ext:///system?command=/tmp/x@y&netcat=s3cr3t",
        "qemu:///system#s3c@r3t",
        # userinfo-shaped text that urlsplit files under the PATH
        "qemu:///root:s3cr3t@hv1/system",
        "qemu:/root:s3cr3t@hv1/system",
        "qemu+ssh:/root:s3cr3t@hv1/system",
        "qemu:root:s3cr3t@hv1/system",
        # a control character inside the userinfo (refused up front)
        "qemu+ssh://root:s3cr3t\n@hv1/system",
        # a secret-shaped scheme is not a libvirt spelling: "(unrecognized)"
        "s3cr3t:///system",
        "s3cr3t" * 20 + ":///system",
        "qemu+s3cr3t:///system",
        # a percent-encoded control character in a value, and a space
        "qemu+unix:///system?socket=/run/libvirt/%0as3cr3t",
        "qemu+unix:///system?socket=/run/libvirt/s3c%20r3t",
    ],
)
def test_no_secret_reaches_log_or_reason(fake_libvirt, uri):
    """Every channel that can carry a refused URI to the journal or telemetry
    -- the reason string and the log line -- is free of the secret token,
    well-formed URI or not, because nothing from the URI is echoed except a
    length-capped scheme."""
    collector, mock_log = _refuse_twice(uri)
    assert [call.args[1] for call in mock_log.call_args_list] == ["error", "debug"]
    logged = [call.args[0] for call in mock_log.call_args_list]
    for text in (collector.refused, *logged):
        assert "s3c" not in text and "r3t" not in text
    fake_libvirt.openReadOnly.assert_not_called()


def test_refusal_log_line_is_bounded_whatever_the_uri_length(fake_libvirt):
    """A backend-supplied URI is unbounded; anything over LIBVIRT_URI_MAX_CHARS
    is refused before it is even parsed (bounding every per-tick parse cost)
    and the log line stays short, so a hostile config cannot stall the tick
    past the systemd watchdog."""
    for uri in (
        "qemu:" + "/" * 200_000,
        "x" * 200_000 + ":///system",
        "qemu:///system?" + "a" * 200_000,
        "qemu:///system?" + "%" * 200_000,
        "qemu://" + "\ufdfa" * 200_000,  # NFKC-expanding netloc
    ):
        with patch("fivenines_agent.qemu.log") as mock_log, patch(
            "fivenines_agent.qemu.urlsplit"
        ) as split:
            collector = QEMUCollector(uri)
        assert collector.refused == "URI is longer than 512 characters"
        split.assert_not_called()  # refused BEFORE any parsing
        assert len(mock_log.call_args_list[0].args[0]) < 250
    fake_libvirt.openReadOnly.assert_not_called()
    # ... and before the cheaper checks too: an over-length URI that would
    # otherwise hit the whitespace or the urlsplit-error branch still reports
    # the length reason, pinning the cap as the FIRST content check.
    for uri in ("qemu:///system?" + "a" * 600 + "\n", "qemu://[" + "a" * 600):
        assert libvirt_uri_rejection(uri) == "URI is longer than 512 characters"


def test_uri_length_cap_leaves_the_longest_legitimate_uri_room():
    """The longest URI libvirt can actually use -- a session socket at the
    107-byte sun_path limit plus mode= -- is well under the cap."""
    longest = "qemu+unix:///session?socket=/run/libvirt/" + "a" * 94 + "&mode=legacy"
    assert len(longest) < qemu.LIBVIRT_URI_MAX_CHARS
    assert libvirt_uri_rejection(longest) is None
    assert libvirt_uri_rejection("qemu:///system?socket=/" + "a" * 600) == (
        "URI is longer than 512 characters"
    )


@pytest.mark.parametrize(
    "uri,shown",
    [
        ("qemu+libssh2://h/system", "'qemu+libssh2'"),
        ("qemu+ext:///system", "'qemu+ext'"),
        ("QEMU+SSH://h/system", "'QEMU+SSH'"),
        ("xen:///system", "(unrecognized)"),
        ("test:///default", "(unrecognized)"),
        ("qemu+unixx:///system", "(unrecognized)"),
        ("a" * 100 + ":///system", "(unrecognized)"),
        ("/var/run/libvirt/libvirt-sock", "(none)"),
    ],
)
def test_scheme_echo_is_drawn_from_libvirt_vocabulary(uri, shown):
    """The scheme is the one token a reason ever echoes, and only when it is
    a libvirt spelling (qemu, or qemu+<known transport>, any case); every
    other spelling is reported as "(unrecognized)" so a secret-shaped scheme
    never reaches the journal."""
    reason = libvirt_uri_rejection(uri)
    assert reason.startswith(f"scheme {shown} is not a local qemu transport")


def test_split_query_reads_parameters_like_virURIParseParams():
    """Pin every claim in _split_query's docstring at once: `&` separates,
    names AND values are percent-decoded, `+` is literal (no form decoding),
    empty segments are skipped, and splitting happens BEFORE decoding so an
    encoded `&` or `=` stays inside its segment instead of minting a new
    parameter -- identical to libvirt on a ";"-free query, except that a
    nameless segment is yielded (and refused upstream) where libvirt drops
    it."""
    pairs = list(
        qemu._split_query("socket=/run/a+b&mode=%64irect&&x%3Dy=%2F&flag&k=v%26w=z&=x")
    )
    assert pairs == [
        ("socket", "/run/a+b"),
        ("mode", "direct"),
        ("x=y", "/"),
        ("flag", ""),
        ("k", "v&w=z"),
        ("", "x"),
    ]
    assert list(qemu._split_query("")) == []


@pytest.mark.parametrize(
    "uri,expected",
    [
        # values are decoded before validation, as libvirt would see them
        ("qemu+unix:///system?socket=%2Frun%2Flibvirt%2Fsock", None),
        ("qemu:///system?mode=%64irect", None),
        # ... so an encoded relative path cannot slip past the absolute check
        ("qemu+unix:///system?socket=%2E%2E%2Fsock", "socket= is not a normalized"),
        # an empty value is not a valid mode
        ("qemu:///system?mode=", "mode= is not one of"),
    ],
)
def test_allowlist_percent_decodes_parameter_values(uri, expected):
    reason = libvirt_uri_rejection(uri)
    if expected is None:
        assert reason is None
    else:
        assert expected in reason


# --- QEMUCollector.__init__: refusal means no libvirt call at all ---


@pytest.mark.parametrize(
    "uri",
    [
        "qemu+ext:///system?command=/tmp/evil",
        "qemu+ssh://root@host/system",
        "qemu+tcp://host/system",
    ],
)
def test_collector_refused_uri_never_touches_libvirt(fake_libvirt, uri):
    with patch("fivenines_agent.qemu.log"):
        collector = QEMUCollector(uri)
    assert collector.conn is None
    assert collector.refused is not None
    fake_libvirt.openReadOnly.assert_not_called()
    fake_libvirt.getVersion.assert_not_called()
    fake_libvirt.getLibVersion.assert_not_called()
    fake_libvirt.registerErrorHandler.assert_not_called()


def test_collector_accepted_uri_connects(fake_libvirt):
    collector = QEMUCollector("qemu+unix:///system?socket=/run/libvirt/libvirt-sock")
    assert collector.refused is None
    fake_libvirt.openReadOnly.assert_called_once_with(
        "qemu+unix:///system?socket=/run/libvirt/libvirt-sock"
    )
    assert collector.conn is fake_libvirt.openReadOnly.return_value
    fake_libvirt.registerErrorHandler.assert_called_once()


def test_collector_default_uri_unchanged(fake_libvirt):
    """Default behaviour: qemu:///system is opened read-only as before."""
    collector = QEMUCollector()
    assert collector.uri == "qemu:///system" == qemu.DEFAULT_LIBVIRT_URI
    assert collector.refused is None
    fake_libvirt.openReadOnly.assert_called_once_with("qemu:///system")


def test_none_uri_refusal_is_an_error_not_debug(fake_libvirt):
    """None is a refusable value ({"uri": null} from the backend) and must
    not collide with the empty log-once register: the first refusal is an
    error (so it reaches telemetry), the repeat is debug."""
    assert qemu._NEVER_REFUSED is not None
    with patch("fivenines_agent.qemu.log") as mock_log:
        QEMUCollector(None)
        QEMUCollector(None)
        # the production reset path must not reintroduce the collision either
        QEMUCollector("qemu:///system")  # accepted: _clear_refusal()
        QEMUCollector(None)
        QEMUCollector(None)
    levels = [
        call.args[1]
        for call in mock_log.call_args_list
        if call.args[0].startswith("Refusing configured libvirt URI")
    ]
    assert levels == ["error", "debug", "error", "debug"]
    assert "non-empty string" in mock_log.call_args_list[0].args[0]
    fake_libvirt.openReadOnly.assert_called_once_with("qemu:///system")


def test_collector_refusal_logged_once_per_change(fake_libvirt):
    """The collector is re-instantiated every tick and the config is
    level-triggered, so a refused URI logs at error once and at debug while
    it repeats; a different refused URI is a new error, and an accepted URI
    in between re-arms the register so a re-introduced bad URI is an error
    again rather than a silent debug line."""
    with patch("fivenines_agent.qemu.log") as mock_log:
        QEMUCollector("qemu+ssh://host/system")
        QEMUCollector("qemu+ssh://host/system")
        # a different URI with the SAME reason is still a change
        QEMUCollector("qemu+ssh://other/system")
        QEMUCollector("qemu+ext:///system?command=/x")
        QEMUCollector("qemu:///system")  # accepted: clears the register
        QEMUCollector("qemu+ext:///system?command=/x")
    refusals = [
        call.args[1]
        for call in mock_log.call_args_list
        if call.args[0].startswith("Refusing configured libvirt URI")
    ]
    assert refusals == ["error", "debug", "error", "error", "error"]
    first = mock_log.call_args_list[0].args[0]
    assert "Refusing configured libvirt URI: scheme 'qemu+ssh'" in first
    assert "host" not in first
    fake_libvirt.openReadOnly.assert_called_once_with("qemu:///system")


def test_connect_disables_session_daemon_autostart(fake_libvirt, monkeypatch):
    """A monitoring agent connects or fails: LIBVIRT_AUTOSTART=0 must already
    be in the environment when openReadOnly runs (libvirt reads it inside the
    open), so the value is captured at call time, not after the fact."""
    monkeypatch.delenv("LIBVIRT_AUTOSTART", raising=False)
    conn = fake_libvirt.openReadOnly.return_value
    seen = []

    def open_read_only(uri):
        seen.append(os.environ.get("LIBVIRT_AUTOSTART"))
        return conn

    fake_libvirt.openReadOnly.side_effect = open_read_only
    QEMUCollector("qemu:///session")
    assert seen == ["0"]
    fake_libvirt.openReadOnly.assert_called_once_with("qemu:///session")


def test_connect_keeps_operator_autostart_override(fake_libvirt, monkeypatch):
    """An explicit LIBVIRT_AUTOSTART in the service environment is the
    operator's call (not the backend's) and stays in force."""
    monkeypatch.setenv("LIBVIRT_AUTOSTART", "1")
    QEMUCollector("qemu:///session")
    assert os.environ["LIBVIRT_AUTOSTART"] == "1"


def test_refused_uri_leaves_environment_untouched(fake_libvirt, monkeypatch):
    monkeypatch.delenv("LIBVIRT_AUTOSTART", raising=False)
    with patch("fivenines_agent.qemu.log"):
        QEMUCollector("qemu+ssh://host/system")
    assert "LIBVIRT_AUTOSTART" not in os.environ


def test_collector_close_is_safe_after_refusal(fake_libvirt):
    with patch("fivenines_agent.qemu.log"):
        collector = QEMUCollector("qemu+ssh://host/system")
    collector.close()  # no connection to close; must not raise
    assert collector.conn is None


# --- qemu_metrics: the payload contract ---


def test_qemu_metrics_no_libvirt():
    """qemu_metrics reports None (nothing collected) when libvirt is not
    installed -- never [] (zero VMs)."""
    with patch("fivenines_agent.qemu.libvirt", None):
        assert qemu_metrics() is None


def test_qemu_metrics_connection_failure_reports_none(fake_libvirt):
    """A failed open is a collection failure, not zero VMs: with
    LIBVIRT_AUTOSTART=0 a session daemon outage now fails the open instead
    of self-healing, and [] here would read as "every VM is gone"."""
    fake_libvirt.openReadOnly.side_effect = RuntimeError("connection refused")
    with patch("fivenines_agent.qemu.log") as mock_log:
        assert qemu_metrics(uri="qemu:///session") is None
    # the accepted-path failure log must not echo the configured URI either
    messages = [call.args[0] for call in mock_log.call_args_list]
    failure = next(m for m in messages if m.startswith("Cannot connect to libvirt"))
    assert failure == "Cannot connect to libvirt: connection refused"
    assert all("qemu:///session" not in m for m in messages)
    fake_libvirt.openReadOnly.return_value = None
    fake_libvirt.openReadOnly.side_effect = None
    with patch("fivenines_agent.qemu.log"):
        assert qemu_metrics() is None


def test_qemu_metrics_enumeration_failure_reports_none(fake_libvirt):
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.side_effect = RuntimeError("daemon went away")
    with patch("fivenines_agent.qemu.log"):
        assert qemu_metrics() is None
    conn.close.assert_called_once()


def test_collect_on_a_refused_collector_is_none(fake_libvirt):
    """The class API matches qemu_metrics: collect() on a refused instance
    is None, with no further log line."""
    with patch("fivenines_agent.qemu.log") as mock_log:
        collector = QEMUCollector("qemu+ssh://host/system")
        assert collector.collect() is None
    assert len(mock_log.call_args_list) == 1


def test_autostart_is_disabled_at_import_before_any_thread_exists():
    """LIBVIRT_AUTOSTART=0 is a process-level setting made once at import on
    the main thread (setenv while another thread may be inside libvirt is
    unsafe on older glibc), so a fresh interpreter importing the module has
    it set without any collector running; an operator value survives."""
    import subprocess
    import sys

    env = {k: v for k, v in os.environ.items() if k != "LIBVIRT_AUTOSTART"}
    code = "import os, fivenines_agent.qemu; print(os.environ['LIBVIRT_AUTOSTART'])"
    out = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True
    )
    assert out.stdout.strip() == "0", out.stderr
    out = subprocess.run(
        [sys.executable, "-c", code],
        env={**env, "LIBVIRT_AUTOSTART": "1"},
        capture_output=True,
        text=True,
    )
    assert out.stdout.strip() == "1", out.stderr


@pytest.mark.parametrize(
    "uri",
    [
        "qemu+ext:///system?command=/tmp/evil",
        "qemu+ssh://root@host/system",
        "qemu://host/system",
        "",
    ],
)
def test_qemu_metrics_refused_uri_reports_none(fake_libvirt, uri):
    """A refused URI is a collection failure (None), never [] -- an empty list
    reads as zero VMs and would prune every VM row on the server."""
    with patch("fivenines_agent.qemu.log"):
        assert qemu_metrics(uri=uri) is None
    fake_libvirt.openReadOnly.assert_not_called()


def test_qemu_metrics_accepted_uri_collects(fake_libvirt):
    conn = fake_libvirt.openReadOnly.return_value
    conn.getInfo.return_value = (None, 2048, 8)
    result = qemu_metrics(uri="qemu:///session")
    fake_libvirt.openReadOnly.assert_called_once_with("qemu:///session")
    assert isinstance(result, list)
    names = {m["name"] for m in result}
    assert {"hypervisor_vcpus_total", "hypervisor_memory_bytes"} <= names
    conn.close.assert_called_once()


def test_qemu_metrics_default_uri_unchanged(fake_libvirt):
    """Default behaviour: config {"qemu": true} splats no kwargs and the
    collector opens qemu:///system exactly as before."""
    result = qemu_metrics()
    fake_libvirt.openReadOnly.assert_called_once_with("qemu:///system")
    assert result == []


# --- collection time bounds (agent #171) ---
#
# No libvirt call carries a timeout, and each monitor call on a VM whose QEMU
# monitor is stuck waits up to 30s for the domain job lock: unbounded, one
# such VM pushed the tick past WatchdogSec=90 and systemd killed the agent.

_DOMAIN_XML = (
    "<domain><devices>"
    "<disk><target dev='vda'/></disk>"
    "<interface><target dev='vnet0'/></interface>"
    "</devices></domain>"
)


def _running_domain(name):
    dom = MagicMock()
    dom.UUIDString.return_value = f"uuid-{name}"
    dom.name.return_value = name
    dom.state.return_value = [1, 0]
    # libvirt's real shape: [state, maxMem, memory, nrVirtCpu, cpuTime]
    dom.info.return_value = [1, 2048, 2048, 2, 1000]
    dom.maxVcpus.return_value = 2
    dom.getCPUStats.return_value = [{"cpu_time": 5}]
    dom.memoryStats.return_value = {"actual": 1024, "rss": 512}
    dom.XMLDesc.return_value = _DOMAIN_XML
    dom.blockStatsFlags.return_value = {"rd_bytes": 1, "wr_bytes": 2}
    dom.interfaceStats.return_value = (1, 2, 0, 0, 3, 4, 0, 0)
    return dom


def _errors(mock_log):
    return [c.args[0] for c in mock_log.call_args_list if c.args[1:] == ("error",)]


def test_domains_are_collected_through_the_budget_check(fake_libvirt):
    """Within budget the per-call check is transparent: a running domain
    yields its full metric set, and a libvirt without blockStatsFlags still
    reads as one (the hasattr fallback sees through the wrapper)."""
    dom, legacy = _running_domain("web"), _running_domain("legacy")
    del legacy.blockStatsFlags
    legacy.blockStats.return_value = (3, 30, 4, 40, 0)
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [dom, legacy]

    result = qemu_metrics()

    by_vm = {}
    for metric in result:
        by_vm.setdefault(metric["labels"]["vm_name"], {})[
            (metric["name"], metric["labels"].get("device"))
        ] = metric["value"]
    assert by_vm["web"][("vm_disk_read_bytes_total", "vda")] == 1
    assert by_vm["web"][("vm_network_receive_bytes_total", "vnet0")] == 1
    assert by_vm["web"][("vm_memory_rss_bytes", None)] == 512 * 1024
    assert by_vm["legacy"][("vm_disk_read_bytes_total", "vda")] == 30
    conn.close.assert_called_once()


def test_a_stuck_monitor_call_bounds_the_tick_and_is_never_doubled(fake_libvirt):
    """The issue's scenario end to end: one VM's memoryStats blocks. The tick
    returns within COLLECT_TIMEOUT with qemu = None (never the VMs collected
    before it) and one telemetry error; the next tick finds the worker still
    blocked and neither opens libvirt again nor logs another error. Once the
    call returns, the timeout backoff still holds the next tick; past it, a
    tick collects afresh."""
    entered, release = threading.Event(), threading.Event()

    def stuck_memory_stats():
        entered.set()
        release.wait(5)
        return {}

    stuck = _running_domain("stuck")
    stuck.memoryStats.side_effect = stuck_memory_stats
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [_running_domain("ok"), stuck]
    try:
        with patch.object(qemu, "COLLECT_TIMEOUT", 0.05):
            data, first, second = {}, {}, {}
            start = time.monotonic()
            collect_metrics({"qemu": True}, data, first, {"qemu": True})
            assert time.monotonic() - start < 1
            assert data == {"qemu": None}
            assert len(first["qemu"]["errors"]) == 1
            assert "blocked for" in first["qemu"]["errors"][0]
            assert qemu._stalled_worker.daemon
            assert entered.wait(5)

            collect_metrics({"qemu": True}, data, second, {"qemu": True})
            assert data == {"qemu": None}
            assert "errors" not in second["qemu"]
            assert fake_libvirt.openReadOnly.call_count == 1
    finally:
        release.set()
        if qemu._stalled_worker is not None:
            qemu._stalled_worker.join(5)

    stuck.memoryStats.side_effect = None
    assert qemu_metrics() is None
    assert fake_libvirt.openReadOnly.call_count == 1

    later = qemu.TIMEOUT_BACKOFF_BASE + 1
    past_backoff = SimpleNamespace(
        monotonic=lambda: time.monotonic() + later, time=time.time
    )
    with patch.object(qemu, "time", past_backoff):
        result = qemu_metrics()
    assert {m["labels"]["vm_name"] for m in result} == {"ok", "stuck"}
    assert fake_libvirt.openReadOnly.call_count == 2


def test_a_spent_budget_reports_none_and_makes_no_further_call(fake_libvirt):
    """The worker's own budget: once a call spends it, the worker makes no
    further libvirt call -- not the rest of this VM, not the next VM -- and
    reports None, never the VMs it got through. The per-metric handlers that
    catch Exception must not swallow it (no error from them, one from the
    budget)."""
    clock = [1000.0]
    slow = _running_domain("slow")

    def slow_memory_stats():
        clock[0] += qemu.COLLECT_BUDGET
        return {}

    slow.memoryStats.side_effect = slow_memory_stats
    later = _running_domain("later")
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [_running_domain("first"), slow, later]
    fake_time = SimpleNamespace(monotonic=lambda: clock[0], time=time.time)

    with patch.object(qemu, "time", fake_time), patch(
        "fivenines_agent.qemu.log"
    ) as mock_log:
        assert qemu_metrics() is None

    slow.XMLDesc.assert_not_called()
    slow.blockStatsFlags.assert_not_called()
    assert later.method_calls == []
    conn.close.assert_called_once()
    errors = _errors(mock_log)
    assert len(errors) == 1
    assert f"past its {qemu.COLLECT_BUDGET}s budget" in errors[0]
    assert qemu._stalled_worker is None


def test_a_spent_budget_escapes_the_hypervisor_totals_handler(fake_libvirt):
    """The hypervisor totals read each domain's state inside two
    `except Exception` blocks; a budget spent there is still None, not the
    totals alone or "listAllDomains failed". A listing that spent the
    budget is reported as the listing."""
    clock = [1000.0]
    fake_time = SimpleNamespace(monotonic=lambda: clock[0], time=time.time)
    dom = _running_domain("a")
    conn = fake_libvirt.openReadOnly.return_value
    conn.getInfo.return_value = (None, 2048, 8)

    def slow_listing():
        clock[0] += qemu.COLLECT_BUDGET
        return [dom]

    conn.listAllDomains.side_effect = slow_listing

    with patch.object(qemu, "time", fake_time), patch(
        "fivenines_agent.qemu.log"
    ) as mock_log:
        assert qemu_metrics() is None

    dom.state.assert_not_called()
    errors = _errors(mock_log)
    assert len(errors) == 1
    assert "budget while listing VMs (0 of 1 VMs done)" in errors[0]


def test_worker_errors_reach_the_ticks_telemetry(fake_libvirt):
    """The collection now logs from its worker; its error lines must still
    land in the dispatcher's telemetry for the tick."""
    fake_libvirt.openReadOnly.side_effect = RuntimeError("connection refused")
    data, telemetry = {}, {}

    collect_metrics({"qemu": True}, data, telemetry, {"qemu": True})

    assert data == {"qemu": None}
    errors = telemetry["qemu"]["errors"]
    assert "Cannot connect to libvirt: connection refused" in errors


def test_the_collection_bounds_are_pinned_and_fit_under_watchdogsec():
    """Every other test monkeypatches the bounds, so nothing there notices the
    SHIPPED values moving. The budget must stay under the timeout: that is
    what lets a merely slow libvirtd finish inside the tick with no abandoned
    worker, and what makes an abandoned worker already past its budget, so it
    stops at its next call instead of queueing another 30s lock wait."""
    unit = Path(__file__).resolve().parent.parent / "fivenines-agent.service"
    watchdog = re.search(r"^WatchdogSec=(\d+)$", unit.read_text(), re.M)
    assert qemu.COLLECT_BUDGET == 10
    assert qemu.COLLECT_TIMEOUT == 15
    assert 0 < qemu.COLLECT_BUDGET < qemu.COLLECT_TIMEOUT
    assert qemu.COLLECT_TIMEOUT < int(watchdog.group(1))
    assert qemu.TIMEOUT_BACKOFF_BASE == 60
    assert qemu.TIMEOUT_BACKOFF_MAX == 120


def test_the_budget_starts_before_the_open(fake_libvirt):
    """Connecting is part of the budget: an open that spends it leaves no time
    for any domain call (None, the domain untouched). The budget gates domain
    calls only, so a slow open onto zero domains is still [] -- libvirt
    answered and listed none."""
    clock = [1000.0]
    conn = fake_libvirt.openReadOnly.return_value

    def slow_open(uri):
        clock[0] += qemu.COLLECT_BUDGET
        return conn

    fake_libvirt.openReadOnly.side_effect = slow_open
    dom = _running_domain("a")
    conn.listAllDomains.return_value = [dom]
    fake_time = SimpleNamespace(monotonic=lambda: clock[0], time=time.time)

    with patch.object(qemu, "time", fake_time), patch(
        "fivenines_agent.qemu.log"
    ) as mock_log:
        assert qemu_metrics() is None
        conn.listAllDomains.return_value = []
        clock[0] += qemu.TIMEOUT_BACKOFF_BASE
        assert qemu_metrics() == []

    assert dom.method_calls == []
    errors = _errors(mock_log)
    assert len(errors) == 1
    assert "budget while opening the libvirt connection" in errors[0]
    assert conn.close.call_count == 2


class _SpendOnLookup:
    """A domain double that spends the whole budget when the collector looks
    up its nth `name` -- inside _Budgeted's getattr, BEFORE its budget check
    -- so the check fails exactly at that call site, under that call site's
    own `except Exception` handler."""

    def __init__(self, dom, name, nth, spend):
        self._dom, self._name, self._left, self._spend = dom, name, nth, spend

    def __getattr__(self, attr):
        if attr == self._name:
            self._left -= 1
            if self._left == 0:
                self._spend()
        return getattr(self._dom, attr)


def _no_per_vcpu_stats(dom):
    dom.getCPUStats.return_value = []
    dom.vcpus.return_value = ([], [])


def _legacy_block_stats(dom):
    del dom.blockStatsFlags
    dom.blockStats.return_value = (3, 30, 4, 40, 0)


@pytest.mark.parametrize(
    "name, nth, setup",
    [
        ("UUIDString", 1, None),  # the per-domain handler
        ("getCPUStats", 1, None),  # per-vCPU stats (libvirtError + Exception)
        ("vcpus", 1, _no_per_vcpu_stats),  # vcpus() fallback
        ("getCPUStats", 2, _no_per_vcpu_stats),  # aggregate CPU stats
        ("info", 1, _no_per_vcpu_stats),  # info() CPU-time fallback
        ("memoryStats", 1, None),
        ("XMLDesc", 1, None),  # _xml_devices
        ("blockStatsFlags", 1, None),  # the hasattr lookup spends it
        ("blockStats", 1, _legacy_block_stats),
        ("interfaceStats", 1, None),
    ],
)
def test_a_spent_budget_escapes_every_per_metric_handler(
    fake_libvirt, name, nth, setup
):
    """Each per-metric helper wraps its libvirt call in `except Exception` to
    skip one bad reading; a budget spent at ANY of them must still end the
    collection as None, with the call itself never made, the next VM never
    touched, and no handler logging it as its own failure (a swallowed
    _BudgetSpent would show up there, since the next call raises it again)."""
    clock = [1000.0]
    mock_log = MagicMock()
    spent_at = []

    def spend():
        spent_at.append(len(mock_log.call_args_list))
        clock[0] += qemu.COLLECT_BUDGET

    dom = _running_domain("target")
    if setup is not None:
        setup(dom)
    later = _running_domain("later")
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [_SpendOnLookup(dom, name, nth, spend), later]
    fake_time = SimpleNamespace(monotonic=lambda: clock[0], time=time.time)

    with patch.object(qemu, "time", fake_time), patch(
        "fivenines_agent.qemu.log", mock_log
    ):
        assert qemu_metrics() is None

    assert getattr(dom, name).call_count == nth - 1
    assert later.method_calls == []
    (first,) = spent_at
    after = [
        c
        for c in mock_log.call_args_list[first:]
        if not c.args[0].startswith("QEMU: no collection attempt")
    ]
    assert len(after) == 1, [c.args for c in after]
    assert after[0].args[1] == "error"
    assert f"past its {qemu.COLLECT_BUDGET}s budget" in after[0].args[0]
    conn.close.assert_called_once()


def test_an_abandoned_worker_stops_at_its_next_call_and_still_closes(fake_libvirt):
    """The tick abandons a worker blocked in a monitor call; by then its
    budget is spent (it is shorter than the timeout), so when the call
    returns the worker makes no further libvirt call -- not the rest of this
    VM, not the next VM -- still closes the connection, and its budget line
    joins the timeout line in that tick's telemetry (the list is shared, see
    debug.adopt_log_capture)."""
    clock = [1000.0]
    entered, release = threading.Event(), threading.Event()

    def stuck_memory_stats():
        entered.set()
        release.wait(5)
        return {}

    stuck = _running_domain("stuck")
    stuck.memoryStats.side_effect = stuck_memory_stats
    later = _running_domain("later")
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [stuck, later]
    fake_time = SimpleNamespace(monotonic=lambda: clock[0], time=time.time)
    data, telemetry = {}, {}

    with patch.object(qemu, "time", fake_time), patch.object(
        qemu, "COLLECT_TIMEOUT", 0.05
    ):
        try:
            collect_metrics({"qemu": True}, data, telemetry, {"qemu": True})
            worker = qemu._stalled_worker
            assert worker.name == "qemu-collect"
            assert entered.wait(5)
            conn.close.assert_not_called()
            clock[0] += qemu.COLLECT_BUDGET
        finally:
            release.set()
            if qemu._stalled_worker is not None:
                qemu._stalled_worker.join(5)
        assert not worker.is_alive()

    assert data == {"qemu": None}
    stuck.XMLDesc.assert_not_called()
    stuck.blockStatsFlags.assert_not_called()
    assert later.method_calls == []
    conn.close.assert_called_once()
    errors = telemetry["qemu"]["errors"]
    assert len(errors) == 2
    assert "blocked for" in errors[0]
    assert "budget" in errors[1]


def test_a_refused_uri_on_the_worker_reaches_telemetry_once(fake_libvirt):
    """The refusal now runs on the collection worker: its error must still
    reach the tick's telemetry, and the log-once register the worker updates
    must be seen by the next tick's worker (debug, no telemetry error)."""
    config = {"qemu": {"uri": "qemu+ssh://host/system"}}
    ticks = []
    for _ in range(2):
        data, telemetry = {}, {}
        collect_metrics(config, data, telemetry, {"qemu": True})
        assert data == {"qemu": None}
        ticks.append(telemetry["qemu"].get("errors", []))

    assert len(ticks[0]) == 1
    assert ticks[0][0].startswith("Refusing configured libvirt URI")
    assert "host" not in ticks[0][0]
    assert ticks[1] == []
    fake_libvirt.openReadOnly.assert_not_called()


def test_a_spent_budget_never_escapes_the_registry(fake_libvirt):
    """_BudgetSpent is a BaseException and call_bounded re-raises whatever
    the worker raised on the caller's thread; the dispatcher only catches
    Exception, so one that escaped qemu_metrics would end the agent loop.
    Through the real registry it is a None payload and one telemetry error."""
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [_running_domain("a")]
    data, telemetry = {}, {}

    with patch.object(qemu, "COLLECT_BUDGET", 0):
        collect_metrics({"qemu": True}, data, telemetry, {"qemu": True})

    assert data == {"qemu": None}
    errors = telemetry["qemu"]["errors"]
    assert len(errors) == 1
    assert "past its 0s budget" in errors[0]


def test_no_libvirt_starts_no_worker():
    """A host without the libvirt module reports None without spawning a
    collection thread every tick."""
    with patch("fivenines_agent.qemu.libvirt", None), patch.object(
        qemu, "call_bounded"
    ) as bounded:
        assert qemu_metrics() is None
    bounded.assert_not_called()
    assert qemu._stalled_worker is None


@pytest.mark.parametrize("hang", ["openReadOnly", "listAllDomains"])
def test_a_hung_connection_call_is_bounded_and_single_flight(fake_libvirt, hang):
    """The open and the enumeration run on the bounded worker too, not only
    the domain calls: a wedged libvirt stack that hangs either one still
    returns the tick within COLLECT_TIMEOUT, the next tick starts no second
    collection, and the worker closes its connection once the call returns."""
    entered, release = threading.Event(), threading.Event()
    conn = fake_libvirt.openReadOnly.return_value

    def hung(*args):
        entered.set()
        release.wait(5)
        return conn if hang == "openReadOnly" else []

    if hang == "openReadOnly":
        fake_libvirt.openReadOnly.side_effect = hung
    else:
        conn.listAllDomains.side_effect = hung
    try:
        with patch.object(qemu, "COLLECT_TIMEOUT", 0.05):
            data, first, second = {}, {}, {}
            start = time.monotonic()
            collect_metrics({"qemu": True}, data, first, {"qemu": True})
            assert time.monotonic() - start < 1
            assert data == {"qemu": None}
            assert "blocked for" in first["qemu"]["errors"][0]
            assert entered.wait(5)

            collect_metrics({"qemu": True}, data, second, {"qemu": True})
            assert data == {"qemu": None}
            assert "errors" not in second["qemu"]
            assert fake_libvirt.openReadOnly.call_count == 1
    finally:
        release.set()
        if qemu._stalled_worker is not None:
            qemu._stalled_worker.join(5)
    conn.close.assert_called_once()


def test_the_budget_line_names_the_vm_it_ran_out_at(fake_libvirt):
    """An operator has to find the stuck VM: the budget line names the VM
    whose call used the last of the budget, and how far the walk got, so a
    stuck VM (same name on every attempt) reads differently from a host too large
    for the budget. The name is repr'd: it is the customer's string."""
    clock = [1000.0]
    stuck = _running_domain("db-prod")

    def slow_memory_stats():
        clock[0] += qemu.COLLECT_BUDGET
        return {}

    stuck.memoryStats.side_effect = slow_memory_stats
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [
        _running_domain("ok"),
        stuck,
        _running_domain("c"),
    ]
    fake_time = SimpleNamespace(monotonic=lambda: clock[0], time=time.time)

    with patch.object(qemu, "time", fake_time), patch(
        "fivenines_agent.qemu.log"
    ) as mock_log:
        assert qemu_metrics() is None

    (error,) = _errors(mock_log)
    assert "budget at VM 'db-prod' (1 of 3 VMs done)" in error


def test_budgeted_passes_non_callable_attributes_through():
    """Reading a plain attribute is no libvirt call: it is returned as is,
    even past the budget, never wrapped in a checking closure."""
    dom = SimpleNamespace(label="vm-a", name=lambda: "vm-a")
    budgeted = qemu._Budgeted(dom, deadline=0)
    assert budgeted.label == "vm-a"
    with pytest.raises(qemu._BudgetSpent):
        budgeted.name()


def test_a_collection_that_ran_out_of_time_backs_off(fake_libvirt):
    """A VM whose monitor stays stuck would otherwise cost the full timeout on
    every tick (its worker ends before the next one, so the single-flight
    never engages). After a collection that spent its budget, none starts for
    TIMEOUT_BACKOFF_BASE seconds, then twice that, capped at
    TIMEOUT_BACKOFF_MAX; one that finishes in time clears the backoff."""
    clock = [1000.0]
    stuck = [True]
    dom = _running_domain("a")

    def memory_stats():
        if stuck[0]:
            clock[0] += qemu.COLLECT_BUDGET
        return {}

    dom.memoryStats.side_effect = memory_stats
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [dom]
    fake_time = SimpleNamespace(monotonic=lambda: clock[0], time=time.time)

    def tick(after):
        clock[0] += after
        return qemu_metrics()

    with patch.object(qemu, "time", fake_time), patch("fivenines_agent.qemu.log"):
        assert tick(0) is None  # spends the budget: backoff 60s
        assert tick(59) is None
        assert fake_libvirt.openReadOnly.call_count == 1
        assert tick(1) is None  # retried, spends it again: backoff 120s
        assert fake_libvirt.openReadOnly.call_count == 2
        assert tick(119) is None
        assert fake_libvirt.openReadOnly.call_count == 2
        assert tick(1) is None  # third: still capped at 120s
        assert qemu._backoff_until == clock[0] + qemu.TIMEOUT_BACKOFF_MAX
        stuck[0] = False
        assert tick(qemu.TIMEOUT_BACKOFF_MAX) is not None  # recovered
        assert fake_libvirt.openReadOnly.call_count == 4
        assert tick(0) is not None  # and no backoff left behind
        assert fake_libvirt.openReadOnly.call_count == 5
        stuck[0] = True  # a new episode starts back at the base
        assert tick(0) is None
        assert qemu._backoff_until == clock[0] + qemu.TIMEOUT_BACKOFF_BASE


def test_a_worker_timeout_backs_off_too(fake_libvirt):
    """The timeout path records the backoff as well, and says so."""
    release = threading.Event()
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.side_effect = lambda: (release.wait(5), [])[1]
    try:
        with patch.object(qemu, "COLLECT_TIMEOUT", 0.05), patch(
            "fivenines_agent.qemu.log"
        ) as mock_log:
            assert qemu_metrics() is None
    finally:
        release.set()
        if qemu._stalled_worker is not None:
            qemu._stalled_worker.join(5)

    (error,) = _errors(mock_log)
    assert f"for at least {qemu.TIMEOUT_BACKOFF_BASE}s and until it returns" in error
    assert qemu_metrics() is None  # worker gone, backoff still holds
    assert fake_libvirt.openReadOnly.call_count == 1


def _qemu_cmdline(uuid):
    return ["/usr/bin/qemu-system-x86_64", "-name", "guest=x", "-uuid", uuid]


class _FakeProcess:
    """psutil.Process over a {pid: (cmdline, create_time)} table; an entry
    that is an exception is raised by the constructor (the process is gone),
    a cmdline that is one by argv() (not ours to read). There is no
    cmdline(): the scan must read a command line through the bounded
    qemu._read_cmdline, which _host_processes serves from the object last
    constructed for that pid."""

    table: dict = {}
    last: dict = {}

    def __init__(self, pid):
        entry = self.table[pid]
        if isinstance(entry, list):  # successive processes on one pid
            entry = entry.pop(0) if len(entry) > 1 else entry[0]
        if isinstance(entry, Exception):
            raise entry
        self._cmdline, self._created = entry
        type(self).last[pid] = self

    def argv(self):
        if isinstance(self._cmdline, Exception):
            raise self._cmdline
        return self._cmdline

    def create_time(self):
        return self._created


@contextlib.contextmanager
def _host_processes(table, process_class=_FakeProcess):
    """Patch the uptime scan's view of the host's processes."""
    fake = type("FakeProcess", (process_class,), {"table": table, "last": {}})
    with patch.multiple(
        qemu.psutil, pids=MagicMock(return_value=list(table)), Process=fake
    ), patch.object(qemu, "_read_cmdline", lambda pid: fake.last[pid].argv()):
        yield


def test_uptime_comes_from_the_qemu_process_start_time(fake_libvirt):
    """libvirt has no API for a domain's start time (dom.info() has five
    fields and none of them is one), so uptime is read from the QEMU process
    libvirt started with `-uuid <domain uuid>`: the older of two processes
    claiming one UUID, 0 for a running VM whose process is not visible, 0 for
    a VM that is not running -- and no libvirt call for any of it."""
    now = time.time()
    web, hidden, off = (
        _running_domain("web"),
        _running_domain("hidden"),
        _running_domain("off"),
    )
    off.state.return_value = [5, 0]
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [web, hidden, off]
    processes = {
        1: psutil.NoSuchProcess(1),  # gone between pids() and Process()
        2: (psutil.AccessDenied(2), now),  # not ours to read
        3: (["bash"], now),
        4: (["qemu", "-uuid"], now),  # no value after -uuid
        5: (_qemu_cmdline("UUID-WEB"), now - 3600),  # the older: needs .lower()
        6: (_qemu_cmdline("uuid-web"), now - 30),
        7: (_qemu_cmdline("uuid-off"), now - 100),
    }

    with _host_processes(processes):
        result = qemu_metrics()
        qemu.psutil.pids.assert_called_once_with()

    uptime = {
        m["labels"]["vm_name"]: m["value"]
        for m in result
        if m["name"] == "vm_vm_uptime_seconds_total"
    }
    assert 3599 <= uptime["web"] <= 3601
    assert uptime["hidden"] == 0
    assert uptime["off"] == 0
    for dom in (web, hidden, off):
        dom.info.assert_not_called()
        assert dom.state.call_count == 1


def test_uptime_is_zero_when_processes_cannot_be_read(fake_libvirt):
    """A failed process scan costs the uptime only, never the collection."""
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [_running_domain("web")]

    no_proc = RuntimeError("no /proc")
    with patch.object(qemu.psutil, "pids", side_effect=no_proc), patch(
        "fivenines_agent.qemu.log"
    ) as mock_log:
        result = qemu_metrics()

    uptime = [m for m in result if m["name"] == "vm_vm_uptime_seconds_total"]
    assert [m["value"] for m in uptime] == [0]
    assert _errors(mock_log) == []


@pytest.mark.parametrize("fail", ["open", "list"])
def test_a_failure_that_is_not_a_timeout_does_not_back_off(fake_libvirt, fail):
    """Only running out of time backs off: a refused connection or a failed
    enumeration (libvirtd restarting) is retried on the very next tick."""
    conn = fake_libvirt.openReadOnly.return_value
    if fail == "open":
        fake_libvirt.openReadOnly.side_effect = [RuntimeError("refused"), conn]
    else:
        conn.listAllDomains.side_effect = [RuntimeError("daemon went away"), []]
    with patch("fivenines_agent.qemu.log"):
        assert qemu_metrics() is None
        assert qemu_metrics() == []
    assert fake_libvirt.openReadOnly.call_count == 2
    assert qemu._backoff_failures == 0


def test_uptime_matches_an_uppercase_domain_uuid_and_is_never_negative(
    fake_libvirt,
):
    """Both sides of the UUID match are case-folded, and a process start time
    ahead of the wall clock (the clock stepped back) reports 0, never a
    negative *_total."""
    now = time.time()
    upper, ahead = _running_domain("upper"), _running_domain("ahead")
    upper.UUIDString.return_value = "UUID-UPPER"
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [upper, ahead]
    processes = {
        1: (_qemu_cmdline("uuid-upper"), now - 600),
        2: (_qemu_cmdline("uuid-ahead"), now + 3600),
    }

    with _host_processes(processes):
        result = qemu_metrics()

    uptime = {
        m["labels"]["vm_name"]: m["value"]
        for m in result
        if m["name"] == "vm_vm_uptime_seconds_total"
    }
    assert 599 <= uptime["upper"] <= 601
    assert uptime["ahead"] == 0


class _FakeLibvirtError(Exception):
    """libvirt.libvirtError's shape: the code comes from get_error_code()."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code

    def get_error_code(self):
        return self.code


VIR_ERR_INTERNAL_ERROR = 1
VIR_ERR_NO_DOMAIN = 42


def test_a_listed_vm_that_cannot_be_read_is_a_failure_not_a_short_list(
    fake_libvirt,
):
    """Behind virtproxyd a restarted virtqemud leaves the agent's own socket
    open: isAlive() still says 1 while every later VM fails. A listed VM that
    cannot be read would be missing from the list, which reads as it being
    gone, so the collection stops there and reports None."""
    a, b, c = _running_domain("a"), _running_domain("b"), _running_domain("c")
    b.state.side_effect = _FakeLibvirtError(
        VIR_ERR_INTERNAL_ERROR, "client socket is closed"
    )
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [a, b, c]
    conn.isAlive.return_value = 1

    with patch("fivenines_agent.qemu.log") as mock_log:
        assert qemu_metrics() is None

    (error,) = _errors(mock_log)
    assert "Cannot read listed VM 'b'" in error
    assert c.method_calls == []
    assert qemu._backoff_failures == 0  # a failure, not running out of time


def test_a_vm_undefined_mid_walk_is_skipped_alone(fake_libvirt):
    """The one VM that may be left out: undefined or destroyed after
    listAllDomains (VIR_ERR_NO_DOMAIN) is really gone."""
    a, b, c = _running_domain("a"), _running_domain("b"), _running_domain("c")
    b.state.side_effect = _FakeLibvirtError(
        VIR_ERR_NO_DOMAIN,
        "Domain not found: no domain with matching uuid 'uuid-b' (b)",
    )
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [a, b, c]

    with patch("fivenines_agent.qemu.log") as mock_log:
        result = qemu_metrics()

    assert {m["labels"]["vm_name"] for m in result} == {"a", "c"}
    assert _errors(mock_log) == []


def test_a_connection_lost_after_the_walk_is_a_failure(fake_libvirt):
    """isAlive() is the complement, read once the walk is over: here the
    last VM's last detail call hits the dropped connection (its handler
    swallows that, and no identity read fails), which is what makes the
    client report it closed. One that cannot answer counts as lost; a live
    one ships the list."""
    a = _running_domain("a")
    state = {"alive": 1}

    def last_call(iface):
        state["alive"] = 0
        raise RuntimeError("End of file while reading data: Input/output error")

    a.interfaceStats.side_effect = last_call
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [a]
    conn.isAlive.side_effect = lambda: state["alive"]

    with patch("fivenines_agent.qemu.log") as mock_log:
        assert qemu_metrics() is None
        assert "connection lost" in _errors(mock_log)[-1]

        conn.isAlive.side_effect = RuntimeError("no connection")
        assert qemu_metrics() is None

        conn.isAlive.side_effect = None
        conn.isAlive.return_value = 1
        result = qemu_metrics()
    assert {m["labels"]["vm_name"] for m in result} == {"a"}


def test_no_domain_needs_libvirts_own_error_code():
    """Only an error carrying libvirt's VIR_ERR_NO_DOMAIN counts as a VM
    that is gone; any other error, or one with no code, does not."""
    with patch.object(qemu, "libvirt", SimpleNamespace(VIR_ERR_NO_DOMAIN=42)):
        assert qemu._is_no_domain(
            _FakeLibvirtError(42, "no domain with matching uuid 'x' (b)")
        )
        assert not qemu._is_no_domain(_FakeLibvirtError(1, "Domain not found"))
        assert not qemu._is_no_domain(RuntimeError("Domain not found"))


@pytest.mark.skipif(
    not os.path.isdir("/proc/self"), reason="the uptime scan reads Linux procfs"
)
def test_uptime_is_read_from_a_real_process_through_private_objects():
    """The real psutil path, which the fakes above cannot vouch for: a child
    started with `-uuid` is found, with its fresh start time, and psutil's
    module-wide process_iter() cache is never touched (the autouse fixture
    makes any use of it fail)."""
    import subprocess
    import sys

    import uuid

    tag = f"TEST-{uuid.uuid4().hex}"  # unique: parallel runs on one host
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)", "-uuid", tag]
    )
    try:
        with patch.object(qemu.psutil, "pids", _REAL_PIDS), patch.object(
            qemu.psutil, "Process", _REAL_PROCESS
        ):
            give_up = time.monotonic() + 30
            started = {}
            while tag.lower() not in started and time.monotonic() < give_up:
                started = qemu._qemu_start_times(float("inf"), {tag.lower()})
        assert started[tag.lower()] == _REAL_PROCESS(child.pid).create_time()
    finally:
        child.kill()
        child.wait()


def test_the_process_scan_counts_against_the_budget(fake_libvirt):
    """The scan runs once, after the walk, and checks the budget per process:
    one that runs out there reports None and says so -- not a VM, not
    libvirt -- and an abandoned worker stops scanning."""
    clock = [1000.0]
    fake_time = SimpleNamespace(monotonic=lambda: clock[0], time=time.time)
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [_running_domain("a")]

    reads = []

    class SlowProcess(_FakeProcess):
        def argv(self):
            reads.append(1)
            clock[0] += qemu.COLLECT_BUDGET
            return super().argv()

    table = {pid: (["bash"], 0.0) for pid in range(3)}
    with patch.object(qemu, "time", fake_time), _host_processes(
        table, SlowProcess
    ), patch("fivenines_agent.qemu.log") as mock_log:
        assert qemu_metrics() is None

    (error,) = _errors(mock_log)
    assert "while reading QEMU process start times (1 of 1 VMs done)" in error
    assert len(reads) == 1  # stopped at the next process, not after the scan


def test_no_process_scan_when_no_vm_is_running(fake_libvirt):
    """Only a running VM has a QEMU process to age."""
    off = _running_domain("off")
    off.state.return_value = [5, 0]
    fake_libvirt.openReadOnly.return_value.listAllDomains.return_value = [off]

    with _host_processes({}):
        result = qemu_metrics()
        qemu.psutil.pids.assert_not_called()
    uptime = [m for m in result if m["name"] == "vm_vm_uptime_seconds_total"]
    assert [m["value"] for m in uptime] == [0]


@pytest.mark.parametrize(
    "where, expected",
    [
        ("open", "while opening the libvirt connection"),
        ("vm", "at VM 'stuck' (1 of 2 VMs done)"),
        ("close", "while closing the libvirt connection (0 of 0 VMs done)"),
    ],
)
def test_the_timeout_line_names_where_the_collection_is_stuck(
    fake_libvirt, where, expected
):
    """libvirt waits for a monitor reply with no timeout, so when the
    agent's own call is the one stuck in a hung QEMU monitor its worker never
    returns and no budget line will ever be written: the tick's own timeout
    line has to say where it is. The tick here stops waiting exactly once the
    worker is inside the hang, so the position is deterministic."""
    entered, release = threading.Event(), threading.Event()
    conn = fake_libvirt.openReadOnly.return_value

    def hang(*args):
        entered.set()
        release.wait(5)
        return conn if where == "open" else {}

    if where == "open":
        fake_libvirt.openReadOnly.side_effect = hang
    elif where == "close":
        conn.close.side_effect = hang
    else:
        stuck = _running_domain("stuck")
        stuck.memoryStats.side_effect = hang
        conn.listAllDomains.return_value = [_running_domain("ok"), stuck]

    def give_up_once_stuck(fn, timeout, name=None):
        worker = threading.Thread(target=fn, name=name, daemon=True)
        worker.start()
        assert entered.wait(5)
        raise qemu.WorkerTimeout(worker, timeout)

    try:
        with patch.object(qemu, "call_bounded", give_up_once_stuck), patch(
            "fivenines_agent.qemu.log"
        ) as mock_log:
            assert qemu_metrics() is None
    finally:
        release.set()
        if qemu._stalled_worker is not None:
            qemu._stalled_worker.join(5)

    (error,) = [e for e in _errors(mock_log) if "blocked for" in e]
    assert expected in error


def test_a_budget_the_last_vm_spent_is_reported_at_that_vm(fake_libvirt):
    """The first budget check after the walk is the scan's: a budget the last
    VM's final call already spent must still be reported at that VM, the one
    a stuck monitor would be in, not at the process scan."""
    clock = [1000.0]
    fake_time = SimpleNamespace(monotonic=lambda: clock[0], time=time.time)
    last = _running_domain("last")

    def slow_interface_stats(iface):
        clock[0] += qemu.COLLECT_BUDGET
        return (1, 2, 0, 0, 3, 4, 0, 0)

    last.interfaceStats.side_effect = slow_interface_stats
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [_running_domain("first"), last]

    with patch.object(qemu, "time", fake_time), patch(
        "fivenines_agent.qemu.log"
    ) as mock_log:
        assert qemu_metrics() is None

    (error,) = _errors(mock_log)
    assert "budget at VM 'last' (2 of 2 VMs done)" in error


def test_one_uptime_row_per_vm_read_even_when_its_details_fail(fake_libvirt):
    """Every VM read gets exactly one uptime row, like its info and state
    rows, including a running VM whose detail metrics fail; a VM that
    vanished mid-walk gets none."""
    from collections import Counter

    now = time.time()
    a, broken, gone = (
        _running_domain("a"),
        _running_domain("broken"),
        _running_domain("gone"),
    )
    broken.maxVcpus.side_effect = RuntimeError("detail read failed")
    gone.state.side_effect = _FakeLibvirtError(VIR_ERR_NO_DOMAIN, "Domain not found")
    conn = fake_libvirt.openReadOnly.return_value
    conn.listAllDomains.return_value = [a, broken, gone]
    processes = {
        1: (_qemu_cmdline("uuid-a"), now - 60),
        2: (_qemu_cmdline("uuid-broken"), now - 120),
    }

    with _host_processes(processes), patch("fivenines_agent.qemu.log"):
        result = qemu_metrics()

    rows = [m for m in result if m["name"] == "vm_vm_uptime_seconds_total"]
    assert Counter(m["labels"]["vm_name"] for m in rows) == {"a": 1, "broken": 1}
    broken_uptime = next(m["value"] for m in rows if m["labels"]["vm_name"] == "broken")
    assert 119 <= broken_uptime <= 121


def test_a_reused_pid_reports_the_new_process_start_time(fake_libvirt):
    """Each scan reads start times through fresh objects: a pid reused by a
    new QEMU process (the VM restarted) reports the new start, never the
    first one seen for that pid."""
    now = time.time()
    fake_libvirt.openReadOnly.return_value.listAllDomains.return_value = [
        _running_domain("web")
    ]

    def uptime_of_web(processes):
        with _host_processes(processes):
            result = qemu_metrics()
        return next(
            m["value"] for m in result if m["name"] == "vm_vm_uptime_seconds_total"
        )

    assert 3599 <= uptime_of_web({7: (_qemu_cmdline("uuid-web"), now - 3600)}) <= 3601
    assert 29 <= uptime_of_web({7: (_qemu_cmdline("uuid-web"), now - 30)}) <= 31


def test_a_pid_reused_while_its_cmdline_is_read_is_skipped(fake_libvirt):
    """The start time is read before the command line and checked again
    after it: a pid that changed owner in between (another process's start
    time) is skipped rather than paired with this UUID."""
    now = time.time()
    fake_libvirt.openReadOnly.return_value.listAllDomains.return_value = [
        _running_domain("web")
    ]
    processes = {
        7: [
            (_qemu_cmdline("uuid-web"), now - 3600),  # read by the scan
            (["bash"], now - 1),  # the pid's owner by the re-check
        ]
    }

    with _host_processes(processes):
        result = qemu_metrics()

    (uptime,) = [
        m["value"] for m in result if m["name"] == "vm_vm_uptime_seconds_total"
    ]
    assert uptime == 0


def test_a_slow_last_process_read_still_spends_the_budget(fake_libvirt):
    """The budget is re-checked after every process, the last one too: a
    final read that overran must not ship a result and clear the backoff."""
    clock = [1000.0]
    fake_time = SimpleNamespace(monotonic=lambda: clock[0], time=time.time)
    fake_libvirt.openReadOnly.return_value.listAllDomains.return_value = [
        _running_domain("a")
    ]

    class SlowLastProcess(_FakeProcess):
        def argv(self):
            clock[0] += qemu.COLLECT_BUDGET
            return super().argv()

    with patch.object(qemu, "time", fake_time), _host_processes(
        {0: (["bash"], 0.0)}, SlowLastProcess
    ), patch("fivenines_agent.qemu.log") as mock_log:
        assert qemu_metrics() is None

    (error,) = _errors(mock_log)
    assert "while reading QEMU process start times" in error
    assert qemu._backoff_failures == 1


def test_the_scan_keeps_only_the_running_vms_uuids():
    """Any local user can start a process with a `-uuid` argument of any size:
    only the running VMs' UUIDs are kept, and an oversized argument is
    refused before it is copied, so unrelated processes cannot grow the
    agent's memory."""
    now = time.time()
    processes = {
        1: (_qemu_cmdline("uuid-a"), now - 60),
        2: (_qemu_cmdline("uuid-not-a-vm-here"), now - 60),
        3: (_qemu_cmdline("x" * (qemu._UUID_MAX_CHARS + 1)), now - 60),
    }
    with _host_processes(processes):
        started = qemu._qemu_start_times(float("inf"), {"uuid-a"})
    assert started == {"uuid-a": now - 60}


def test_an_oversized_uuid_argument_is_refused_before_it_is_copied():
    """The length is checked on the raw argument: one exactly at the limit
    that is wanted is kept, one past it never reaches .lower()."""
    at_limit = "A" * qemu._UUID_MAX_CHARS
    now = time.time()
    copied = []

    class Arg(str):
        def lower(self):  # recorded, not raised: the scan swallows errors
            copied.append(len(self))
            return str.lower(self)

    processes = {
        1: (["qemu", "-uuid", at_limit], now - 5),
        2: (["qemu", "-uuid", Arg("B" * (qemu._UUID_MAX_CHARS + 1))], now - 5),
    }
    with _host_processes(processes):
        started = qemu._qemu_start_times(float("inf"), {at_limit.lower()})
    assert started == {at_limit.lower(): now - 5}
    assert copied == []


class _CountingFile:
    """A file whose reads are counted, to prove a bounded read stays bounded."""

    def __init__(self, f, counted):
        self._f, self._counted = f, counted

    def read(self, n):
        chunk = self._f.read(n)
        self._counted.append(len(chunk))
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._f.close()


def test_cmdline_is_read_bounded_straight_from_procfs(tmp_path):
    """A normal command line is split on NUL; one past _CMDLINE_MAX_BYTES is
    skipped after reading at most one byte past the limit -- never the whole
    thing, which any local user can make megabytes long; a pid that is gone
    raises, and the scan skips it."""
    (tmp_path / "1.cmdline").write_bytes(b"qemu\0-uuid\0ABC\0")
    (tmp_path / "2.cmdline").write_bytes(b"x" * 100_000)
    counted = []
    real_open = open

    def counting_open(*args, **kwargs):
        return _CountingFile(real_open(*args, **kwargs), counted)

    with patch.object(
        qemu, "_PROC_CMDLINE", str(tmp_path / "{}.cmdline")
    ), patch.object(qemu, "_CMDLINE_MAX_BYTES", 16), patch(
        "fivenines_agent.qemu.open", counting_open, create=True
    ):
        assert qemu._read_cmdline(1) == ["qemu", "-uuid", "ABC", ""]
        counted.clear()
        assert qemu._read_cmdline(2) is None
        assert sum(counted) == 17
        with pytest.raises(OSError):
            qemu._read_cmdline(3)
