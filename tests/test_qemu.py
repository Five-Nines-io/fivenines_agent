"""Tests for fivenines_agent.qemu module.

The libvirt URI allowlist (agent #142) is the focus: a libvirt URI selects a
transport, and `ext` / `ssh` / `tcp` transports execute a local command or
dial out regardless of openReadOnly(), so the collector must refuse to open
anything but the local hypervisor socket -- with NO libvirt call on refusal
and a None payload (collection failure) rather than [] (zero VMs).
"""

import os
from unittest.mock import patch

import pytest

import fivenines_agent.qemu as qemu
from fivenines_agent.qemu import QEMUCollector, libvirt_uri_rejection, qemu_metrics

# The log-once register (qemu._last_refused_uri) is module-level state; the
# autouse fixture in tests/conftest.py resets it before every test.


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
        # directory: the open has no timeout, and any other local socket
        # could stall the tick (docker.sock reads and waits) or start a
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
