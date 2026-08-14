"""Tests for the Tailscale node/tailnet collector (#508 / agent #127).

Only the subprocess boundary is mocked: each case feeds a canned `tailscale
status --json` document back through the real parse -> payload pipeline. The
cross-repo round-trip lives in test_vpn_contract.py.
"""

import json
import subprocess

import pytest

from fivenines_agent import tailscale
from fivenines_agent.tailscale import tailscale_metrics


def _status(**overrides):
    doc = {
        "Version": "1.86.2-t01e4dc5f2",
        "BackendState": "Running",
        "Self": {
            "HostName": "edge-01",
            "Online": True,
            "KeyExpiry": "2026-09-15T10:00:00Z",
        },
        "Peer": {
            "nodekey:a": {"HostName": "peer-a", "Online": True},
            "nodekey:b": {"HostName": "peer-b", "Online": False},
        },
    }
    doc.update(overrides)
    return doc


@pytest.fixture
def ts(monkeypatch):
    """Install a fake `tailscale` CLI. Returns a callable arming the next run."""
    monkeypatch.setattr(tailscale.shutil, "which", lambda _: "/usr/bin/tailscale")

    def install(document=None, stdout=None, returncode=0, stderr="", raises=None):
        if stdout is None:
            stdout = "" if document is None else json.dumps(document)

        def fake_run(*_args, **_kwargs):
            if raises is not None:
                raise raises
            return subprocess.CompletedProcess(
                ["tailscale", "status", "--json"],
                returncode,
                stdout=stdout,
                stderr=stderr,
            )

        monkeypatch.setattr(tailscale.subprocess, "run", fake_run)

    return install


# --- binary resolution -----------------------------------------------------


def test_missing_cli_is_a_collection_failure(monkeypatch):
    monkeypatch.setattr(tailscale.shutil, "which", lambda _: None)
    monkeypatch.setattr(tailscale.os.path, "isfile", lambda _: False)
    assert tailscale_metrics() is None


def test_off_path_install_is_found(monkeypatch):
    """The macOS App Store build lives inside the app bundle, and a Windows
    service account can have the CLI off its PATH."""
    bundled = tailscale._EXTRA_BINARY_PATHS[0]
    monkeypatch.setattr(tailscale.shutil, "which", lambda _: None)
    monkeypatch.setattr(tailscale.os.path, "isfile", lambda p: p == bundled)
    assert tailscale._tailscale_binary() == bundled


# --- collection failure ----------------------------------------------------


def test_spawn_error_is_a_collection_failure(ts):
    ts(raises=OSError("no such thing"))
    assert tailscale_metrics() is None


def test_timeout_is_a_collection_failure(ts):
    ts(raises=subprocess.TimeoutExpired(cmd="tailscale", timeout=10))
    assert tailscale_metrics() is None


def test_unreachable_daemon_is_a_collection_failure(ts):
    ts(returncode=1, stderr="failed to connect to local tailscaled")
    assert tailscale_metrics() is None


def test_unreachable_daemon_without_stderr_is_a_collection_failure(ts):
    ts(returncode=1)
    assert tailscale_metrics() is None


def test_unparseable_output_is_a_collection_failure(ts):
    ts(stdout="not json at all")
    assert tailscale_metrics() is None


def test_non_object_output_is_a_collection_failure(ts):
    ts(stdout="[1, 2, 3]")
    assert tailscale_metrics() is None


@pytest.mark.parametrize("state", [None, "", "   ", 7])
def test_document_without_a_backend_state_is_a_collection_failure(ts, state):
    ts(document=_status(BackendState=state))
    assert tailscale_metrics() is None


# --- successful reads ------------------------------------------------------


def test_healthy_payload(ts):
    ts(document=_status())
    assert tailscale_metrics() == {
        "backend_state": "Running",
        "self": {
            "hostname": "edge-01",
            "key_expiry": "2026-09-15T10:00:00Z",
            "online": True,
        },
        "peers_total": 2,
        "peers_online": 1,
    }


def test_needs_login_is_a_successful_read_not_a_failure(ts):
    """The silent killer: an expired node key leaves tailscaled alive in
    NeedsLogin, off the tailnet, with no error anywhere on the box. Reporting
    null here would make the server preserve the last-known 'Running' block and
    hide the outage the feature exists to catch."""
    ts(
        document=_status(
            BackendState="NeedsLogin",
            Self={
                "HostName": "edge-03",
                "Online": False,
                "KeyExpiry": "2026-08-01T00:00:00Z",
            },
            Peer=None,
        )
    )
    payload = tailscale_metrics()
    assert payload["backend_state"] == "NeedsLogin"
    assert payload["peers_total"] == 0
    assert payload["peers_online"] == 0


def test_nonzero_exit_with_a_valid_document_is_still_a_successful_read(ts):
    """`tailscale status` exits 1 when the node is not up. Its --json branch
    returns before that check today, but the outcome must hang on whether we got
    a status document, not on the exit code."""
    ts(document=_status(BackendState="Stopped"), returncode=1)
    assert tailscale_metrics()["backend_state"] == "Stopped"


def test_backend_state_travels_verbatim(ts):
    """tailscale owns this vocabulary and extends it; never map it to an enum."""
    ts(document=_status(BackendState="  SomeFutureState  "))
    assert tailscale_metrics()["backend_state"] == "SomeFutureState"


@pytest.mark.parametrize("self_block", [None, "junk", []])
def test_missing_self_block_is_a_collection_failure(ts, self_block):
    """key_expiry: null contractually means "expiry is DISABLED for this node",
    NOT "we could not read it". Publishing a null-everything Self on a degraded
    document would silently switch OFF expiry monitoring for a node whose key is
    about to expire -- the exact outage this collector exists to catch. No Self
    means no reading, so the server keeps the last known good block."""
    ts(document=_status(Self=self_block))
    assert tailscale_metrics() is None


def test_non_dict_peer_map_reads_zero(ts):
    ts(document=_status(Peer=["unexpected"]))
    payload = tailscale_metrics()
    assert (payload["peers_total"], payload["peers_online"]) == (0, 0)


def test_non_dict_peer_entries_are_not_counted_online(ts):
    ts(document=_status(Peer={"a": "junk", "b": {"Online": True}}))
    payload = tailscale_metrics()
    assert (payload["peers_total"], payload["peers_online"]) == (2, 1)


def test_blank_hostname_is_null(ts):
    ts(document=_status(Self={"HostName": "   ", "Online": True}))
    assert tailscale_metrics()["self"]["hostname"] is None


def test_non_string_hostname_is_null(ts):
    ts(document=_status(Self={"HostName": 42, "Online": True}))
    assert tailscale_metrics()["self"]["hostname"] is None


def test_self_online_is_coerced_and_absence_stays_null(ts):
    ts(document=_status(Self={"HostName": "edge", "Online": 1}))
    assert tailscale_metrics()["self"]["online"] is True
    ts(document=_status(Self={"HostName": "edge"}))
    assert tailscale_metrics()["self"]["online"] is None


# --- key expiry ------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("2026-09-15T10:00:00Z", "2026-09-15T10:00:00Z"),
        ("2026-09-15T10:00:00z", "2026-09-15T10:00:00Z"),
        # Go's RFC3339Nano carries 9 fractional digits; fromisoformat takes 6.
        ("2026-08-14T06:00:00.482913741Z", "2026-08-14T06:00:00Z"),
        # A non-UTC offset is normalized, not passed through.
        ("2026-09-15T12:00:00+02:00", "2026-09-15T10:00:00Z"),
        # A naive instant is read as UTC rather than local time.
        ("2026-09-15T10:00:00", "2026-09-15T10:00:00Z"),
    ],
)
def test_key_expiry_is_normalized(raw, expected):
    assert tailscale._key_expiry(raw) == expected


@pytest.mark.parametrize("raw", [None, 1234, "", "   ", "0001-01-01T00:00:00Z"])
def test_key_expiry_disabled_reads_null(raw):
    """null means expiry is DISABLED for the node ("never expires"), not
    "unknown". Tailscale says it two ways: the field is omitted (Go's omitempty
    on a nil *time.Time) or it carries the zero time."""
    assert tailscale._key_expiry(raw) is None


def test_unparseable_expiry_is_passed_through_verbatim():
    """The server parses tolerantly and clamps; silently nulling a real deadline
    is the one outcome worse than a messy string."""
    assert tailscale._key_expiry(" someday ") == "someday"


def test_unparseable_expiry_is_bounded():
    """key_expiry is the one field the server does not truncate (it Time.parses
    it), so the verbatim passthrough must bound it itself."""
    assert len(tailscale._key_expiry("x" * 5000)) == tailscale._MAX_EXPIRY_CHARS


def test_absurd_expiry_offset_does_not_raise():
    assert tailscale._key_expiry("0001-01-01T00:00:00+05:00") == (
        "0001-01-01T00:00:00+05:00"
    )
