"""Tailscale node + tailnet state collector (server #508).

This half of the VPN feature exists for ONE failure mode: an expired node key
silently drops the machine off the tailnet. tailscaled stays alive, flips to
`NeedsLogin`, and nothing on the box logs an error while every tailnet-only
service stops answering. `tailscale status --json` is the only place that
shows it.

Contract rules (contract fixture: tests/fixtures/vpn_contract_payload.json):

- ROLLUPS ONLY. Every node sees every tailnet peer, so per-peer rows would cost
  hosts x peers series across a fleet. Only `peers_total` / `peers_online`
  travel (the systemd #562 rollup precedent).
- `backend_state` is tailscale's own vocabulary verbatim as a string, never an
  enum: they extend it.
- `self.key_expiry` is ``None`` when key expiry is DISABLED for the node -- a
  legitimate admin-console setting meaning "never expires", not "unknown". The
  server then emits no expiry sample at all rather than charting 0 days left.
- ``None`` for the WHOLE payload means the CLI/daemon could not be reached, so
  the server preserves the last-known block instead of blanking it. Being OFF
  the tailnet is a SUCCESSFUL read carrying `Stopped` / `NeedsLogin` -- never
  ``None``.

Cross-OS: tailscaled and `tailscale status --json` are identical on Linux,
Windows and macOS, so unlike the WireGuard half this key is never stripped for
Windows agents.
"""

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone

from fivenines_agent.debug import debug, log
from fivenines_agent.subprocess_utils import get_clean_env

# Hard subprocess timeout (seconds). `tailscale status` talks to a local unix
# socket / named pipe and answers immediately; the ceiling only keeps a wedged
# daemon out of the watchdog-bounded collect tick.
_SUBPROCESS_TIMEOUT = 10

# Install locations that are NOT on PATH. The macOS App Store build ships inside
# the app bundle, and a Windows service install can leave the CLI off a service
# account's PATH. Both are checked only after shutil.which() misses.
_EXTRA_BINARY_PATHS = (
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    "C:\\Program Files\\Tailscale\\tailscale.exe",
)

# Trims sub-second precision to the 6 digits datetime.fromisoformat accepts.
# tailscale emits Go's RFC3339Nano, which can carry 9.
_FRACTION_RE = re.compile(r"\.(\d+)")

# Ceiling on an unparseable key_expiry passed through verbatim. RFC3339Nano with
# an offset is 35 chars; this is generous and still bounds the payload.
_MAX_EXPIRY_CHARS = 64


def _tailscale_binary():
    found = shutil.which("tailscale")
    if found:
        return found
    for path in _EXTRA_BINARY_PATHS:
        if os.path.isfile(path):
            return path
    return None


def _run_status():
    """Return the parsed `tailscale status --json` document, or None.

    The exit code is deliberately NOT the gate. `tailscale status` exits 1 when
    the node is not up, but its --json branch returns before that check, so a
    logged-out daemon prints a complete document and exits 0 -- and a future
    build could just as well print the document and exit 1. What decides the
    outcome here is whether we got a status document at all: one carrying a
    BackendState is a successful read no matter what the exit code said, and
    `Stopped` / `NeedsLogin` inside it is the signal, not a failure. Only when
    there is no parseable document is this a genuine collection failure.
    """
    binary = _tailscale_binary()
    if binary is None:
        log("Tailscale: `tailscale` not found in PATH", "debug")
        return None

    try:
        result = subprocess.run(
            [binary, "status", "--json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=_SUBPROCESS_TIMEOUT,
            env=get_clean_env(),
        )
    except (OSError, subprocess.SubprocessError) as e:
        log(f"Tailscale: `tailscale status --json` failed: {e}", "error")
        return None

    stdout = (result.stdout or "").strip()
    if not stdout:
        log(
            "Tailscale: `tailscale status --json` returned no output: "
            f"{(result.stderr or '').strip() or 'no error output'}",
            "error",
        )
        return None

    try:
        parsed = json.loads(stdout)
    except ValueError as e:
        log(f"Tailscale: could not parse `tailscale status --json`: {e}", "error")
        return None

    if not isinstance(parsed, dict):
        log("Tailscale: `tailscale status --json` was not an object", "error")
        return None

    state = parsed.get("BackendState")
    if not isinstance(state, str) or not state.strip():
        log("Tailscale: status document carried no BackendState", "error")
        return None

    # Self is required, not optional. tailscaled always includes it when it
    # answers at all -- even logged out. Accepting a document without it would
    # publish key_expiry: null, and null contractually means "expiry is DISABLED
    # for this node", not "we could not read it". A shape change or a degraded
    # response would then silently switch OFF expiry monitoring on nodes whose
    # keys are about to expire, which is the one outage this collector exists to
    # catch. No Self means no reading: report null and let the server keep the
    # last known good block.
    self_raw = parsed.get("Self")
    if not isinstance(self_raw, dict):
        log("Tailscale: status document carried no Self block", "error")
        return None

    # Same argument one level down. ABSENT or null KeyExpiry is the legitimate
    # "expiry disabled" reading (Go's omitempty on a nil *time.Time). But a
    # KeyExpiry that is PRESENT and not a string is a shape change, and mapping
    # it to None would again publish "expiry disabled" for a node that may be
    # days from dropping off the tailnet.
    expiry = self_raw.get("KeyExpiry")
    if expiry is not None and not isinstance(expiry, str):
        log(f"Tailscale: KeyExpiry was {type(expiry).__name__}, not a string", "error")
        return None

    # And once more for the peer map. Absent or null Peer is the legitimate
    # logged-out reading (0/0). A Peer that is present but not an object is a
    # shape change, and silently counting it as zero would report an empty
    # tailnet the node cannot actually see.
    peers = parsed.get("Peer")
    if peers is not None and not isinstance(peers, dict):
        log(f"Tailscale: Peer was {type(peers).__name__}, not an object", "error")
        return None

    return parsed


def _clean_str(value):
    if not isinstance(value, str):
        return None
    return value.strip() or None


def _parse_rfc3339(raw):
    text = raw
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    text = _FRACTION_RE.sub(lambda m: "." + m.group(1)[:6], text, count=1)
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def _key_expiry(value):
    """Normalize Self.KeyExpiry to a canonical ISO-8601 UTC instant, or None.

    None means key expiry is DISABLED for this node -- "never expires", not
    "unknown". Tailscale expresses that two ways and both land here: the field
    is omitted entirely (Go's omitempty on a nil *time.Time), or it carries the
    zero time (0001-01-01T00:00:00Z). An unparseable value is passed through
    verbatim rather than dropped: the server parses tolerantly and clamps, and
    silently nulling a real deadline is the one outcome worse than a messy
    string.
    """
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None

    parsed = _parse_rfc3339(raw)
    if parsed is None:
        # Verbatim, but bounded. This is the one field the server does not
        # truncate (it Time.parses it), so an absurd string would otherwise ride
        # the whole tick. A real RFC3339 instant is well under this.
        return raw[:_MAX_EXPIRY_CHARS]
    if parsed.year <= 1:
        return None
    return (
        f"{parsed.year:04d}-{parsed.month:02d}-{parsed.day:02d}"
        f"T{parsed.hour:02d}:{parsed.minute:02d}:{parsed.second:02d}Z"
    )


@debug("tailscale")
def tailscale_metrics():
    """Collect Tailscale node state and tailnet rollups.

    Returns ``None`` on a collection failure (CLI missing, daemon socket
    unreachable, unparseable output), or the state block. A reachable daemon
    that is off the tailnet is NOT a failure: it reports its real
    `backend_state` and the server drives `tailscale_up` from it.
    """
    status = _run_status()
    if status is None:
        return None

    # _run_status has already established that Self is a dict, that KeyExpiry
    # is absent/null/str, and that Peer is absent/null/dict.
    self_raw = status["Self"]
    peers = status.get("Peer") or {}
    peers_online = sum(
        1 for peer in peers.values() if isinstance(peer, dict) and peer.get("Online")
    )

    self_online = self_raw.get("Online")
    return {
        "backend_state": status["BackendState"].strip(),
        "self": {
            "hostname": _clean_str(self_raw.get("HostName")),
            "key_expiry": _key_expiry(self_raw.get("KeyExpiry")),
            "online": None if self_online is None else bool(self_online),
        },
        "peers_total": len(peers),
        "peers_online": peers_online,
    }
