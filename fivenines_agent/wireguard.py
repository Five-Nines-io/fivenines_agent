"""WireGuard peer health collector (server #508).

MSPs run WireGuard to every customer site, so a dead tunnel means blind
monitoring of everything behind it. One `wg show all dump` per tick produces the
full current set of interfaces and peers; the server turns each peer into a
first-class row so `wireguard_peer_stale` fires per tunnel.

Three contract rules this module exists to honour (contract fixture:
tests/fixtures/vpn_contract_payload.json):

1. SECRETS NEVER TRAVEL. `wg show all dump` prints the interface PRIVATE KEY as
   the second field of every interface line and each peer's PRESHARED KEY as the
   third field of every peer line. Both are dropped here and never enter the
   payload; the server has no column for either. Only the peer PUBLIC key
   travels -- it is public by construction and is the peer's durable identity.

2. null AND [] MEAN OPPOSITE THINGS. ``None`` is a COLLECTION FAILURE (`wg`
   missing, no CAP_NET_ADMIN, timeout, a partial view) and the server touches
   nothing. ``{"peers": []}`` is a successful read of a host with genuinely zero
   peers and is the documented PRUNE-ALL. Reporting `[]` on a privilege failure
   would mass-false-resolve every open `wireguard_peer_stale` incident, so every
   ambiguous outcome here resolves to ``None``.

3. AGES, NOT TIMESTAMPS. `last_handshake_age_seconds` is computed from the
   agent's own clock and anchored server-side to `received_at`, so a skewed
   agent clock can never make a dead tunnel look fresh.

PRIVILEGE: `wg show all dump` needs root or CAP_NET_ADMIN. The packaged systemd
unit grants ``AmbientCapabilities=CAP_NET_ADMIN`` rather than running as root.
"""

import os
import re
import shutil
import subprocess
import time

from fivenines_agent.debug import debug, log
from fivenines_agent.subprocess_utils import get_clean_env

# Hard subprocess timeout (seconds). `wg` reads kernel state over netlink and
# answers in milliseconds, so 10s is generous; the ceiling exists only so a
# wedged call can never eat into the watchdog-bounded collect tick. Mirrors the
# zfs/ceph SUBPROCESS_TIMEOUT posture.
_SUBPROCESS_TIMEOUT = 10

# wg-quick config location, read best-effort for the operator alias only.
_WG_CONFIG_DIR = "/etc/wireguard"

# Cap on how much of a wg-quick config is read. A real config is a few KiB; the
# bound just keeps a pathological file off the collect tick.
_MAX_CONFIG_BYTES = 1024 * 1024

# `wg show all dump` field counts. With "all" every line is prefixed by the
# interface name, so an interface line carries 5 fields and a peer line 9.
_INTERFACE_FIELDS = 5
_PEER_FIELDS = 9

# wg's sentinels for "unset".
_NONE_SENTINEL = "(none)"
_OFF_SENTINEL = "off"

# The operator alias convention: a "# Name = ..." comment on (or immediately
# before) a [Peer] block. Nothing else is ever read out of a wg-quick config --
# in particular not PrivateKey or PresharedKey.
_NAME_COMMENT_RE = re.compile(r"^[#;]\s*Name\s*=\s*(.*)$", re.IGNORECASE)
_PUBLIC_KEY_RE = re.compile(r"^PublicKey\s*=\s*(\S+)\s*$", re.IGNORECASE)


def _run_wg_dump():
    """Return `wg show all dump` stdout, or None on any failure or partial view.

    None is returned for four distinct outcomes, all of which are collection
    failures under the contract:

    - `wg` is not installed;
    - the process could not be spawned, or timed out;
    - a non-zero exit;
    - ANY output on stderr.

    That last rule is the load-bearing one. Without CAP_NET_ADMIN, `wg` can
    still enumerate interface NAMES (an unprivileged rtnetlink call) but not
    read them, so it prints "Unable to access interface wg0: Operation not
    permitted" per interface and can still exit 0 with empty or PARTIAL stdout.
    Treating that as a successful read would ship a short peer list, which the
    server is contractually required to read as a full set and vanish-prune.
    Any stderr chatter therefore means "this view is not trustworthy" and the
    tick reports null: a data gap is recoverable, a false prune resolves live
    incidents.
    """
    if shutil.which("wg") is None:
        log("WireGuard: `wg` not found in PATH", "debug")
        return None

    try:
        result = subprocess.run(
            ["wg", "show", "all", "dump"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=_SUBPROCESS_TIMEOUT,
            env=get_clean_env(),
        )
    except (OSError, subprocess.SubprocessError) as e:
        log(f"WireGuard: `wg show all dump` failed: {e}", "error")
        return None

    if result.returncode != 0:
        log(
            "WireGuard: `wg show all dump` exited "
            f"{result.returncode}: {(result.stderr or '').strip() or 'no output'}",
            "error",
        )
        return None

    stderr = (result.stderr or "").strip()
    if stderr:
        log(f"WireGuard: incomplete `wg show all dump` view: {stderr}", "error")
        return None

    return result.stdout or ""


def _clean(value):
    """Map wg's "(none)" sentinel (and blanks) to None, else the trimmed value."""
    trimmed = value.strip()
    if not trimmed or trimmed == _NONE_SENTINEL:
        return None
    return trimmed


def _to_int(value, default=None):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _listen_port(value):
    """UDP listen port, or None for a client interface with no fixed port."""
    port = _to_int(value)
    return port or None


def _keepalive(value):
    """Keepalive interval in seconds, or None when off.

    LOAD-BEARING: WireGuard is silent by design, so a peer WITHOUT keepalive can
    be idle-but-healthy with an arbitrarily old handshake. The server's
    `wireguard_peer_stale` trigger watches only keepalive-configured peers by
    default, so mislabelling "off" as an interval would page on healthy idle
    laptops.
    """
    trimmed = (value or "").strip()
    if not trimmed or trimmed in (_OFF_SENTINEL, _NONE_SENTINEL):
        return None
    return _to_int(trimmed) or None


def _handshake_age(value, now):
    """Seconds since the last completed handshake, or None when there was none.

    `wg` reports latest-handshake=0 for a peer that has never completed a
    handshake since the interface came up. That is None, deliberately NOT 0: the
    server anchors a null age to the row's first_seen_at instead of charting a
    fresh handshake that never happened.

    A NEGATIVE age -- the handshake timestamp is in the future, which happens
    when the clock steps backwards (NTP correcting a skewed host, a VM restored
    from a snapshot) -- is also None, and this one is load-bearing. Clamping it
    to 0 would be far worse than useless: the server computes
    ``last_handshake_at = received_at - age`` and keeps the NEWEST of that and
    the stored anchor, so an age of 0 overwrites a real, older handshake with
    "just now" and silently resolves an open wireguard_peer_stale incident for a
    tunnel that is actually dead. None instead means "no reading this tick", the
    server keeps the true anchor, and the age keeps growing until the peer
    really does come back. Nonsense data must never outrank real data.
    """
    timestamp = _to_int(value)
    if not timestamp:
        return None
    age = int(now) - timestamp
    if age < 0:
        return None
    return age


def _parse_dump(text, now):
    """Parse `wg show all dump` into (interfaces, peers).

    Interface lines are ``name  PRIVATE-KEY  public-key  listen-port  fwmark``
    and peer lines ``name  public-key  PRESHARED-KEY  endpoint  allowed-ips
    latest-handshake  rx  tx  keepalive``. The two secret columns are indexed
    past and never read.
    """
    interfaces = []
    peers = []
    by_name = {}

    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")

        if len(fields) == _INTERFACE_FIELDS:
            name = fields[0].strip()
            if not name:
                continue
            # fields[1] is the interface PRIVATE KEY and fields[2] its public
            # key: neither is read, neither has a server column.
            entry = {
                "name": name,
                "listen_port": _listen_port(fields[3]),
                "peer_count": 0,
            }
            interfaces.append(entry)
            by_name[name] = entry
            continue

        if len(fields) != _PEER_FIELDS:
            continue

        interface = fields[0].strip()
        public_key = fields[1].strip()
        if not interface or not public_key:
            continue
        # fields[2] is the peer PRESHARED KEY: not read, never transmitted.
        peers.append(
            {
                "interface": interface,
                "public_key": public_key,
                "name": None,
                "endpoint": _clean(fields[3]),
                "allowed_ips": _clean(fields[4]),
                "last_handshake_age_seconds": _handshake_age(fields[5], now),
                "rx_bytes": _to_int(fields[6], 0),
                "tx_bytes": _to_int(fields[7], 0),
                "persistent_keepalive": _keepalive(fields[8]),
            }
        )
        if interface in by_name:
            by_name[interface]["peer_count"] += 1

    return interfaces, peers


def _read_wg_quick_config(interface):
    """Best-effort read of /etc/wireguard/<interface>.conf, or None.

    wg-quick configs are mode 0600 in a 0700 directory because they carry the
    interface PRIVATE KEY, so an agent running as `fivenines` with only
    CAP_NET_ADMIN gets None here and every peer alias stays null -- the server
    then renders a short key fingerprint. That degradation is intentional: the
    alias is a nicety, the peer's public key is its identity.
    """
    if not interface or os.sep in interface or (os.altsep and os.altsep in interface):
        return None
    path = os.path.join(_WG_CONFIG_DIR, f"{interface}.conf")
    try:
        with open(path, "r", errors="replace") as handle:
            return handle.read(_MAX_CONFIG_BYTES)
    except (OSError, ValueError):
        # ValueError covers open()'s embedded-null-byte rejection. An alias is
        # best-effort by contract, so every read failure must degrade to "no
        # alias" rather than raise and turn the whole tick into a null payload.
        return None


def _parse_peer_aliases(text):
    """Map peer public key -> operator alias from a wg-quick config.

    Accepts the alias comment either immediately before the ``[Peer]`` header
    (the de-facto convention) or inside the block, which are textually the same
    thing once blank lines are dropped. The tie-breaker is the block's own
    ``PublicKey``: a comment seen BEFORE it names this peer, one seen after it
    is the header of the NEXT block. Without that rule the extremely common

        [Peer]
        PublicKey = <a>

        # Name = bob
        [Peer]
        PublicKey = <b>

    layout would label peer <a> "bob" -- silently mislabelling every peer in the
    file by one.

    Only the alias comment and ``PublicKey`` lines are looked at; ``PrivateKey``
    and ``PresharedKey`` are never matched, so no secret can leak into the
    payload through this path.
    """
    aliases = {}
    pending_name = None
    in_peer = False
    key = None
    name = None

    def flush():
        nonlocal key, name
        if in_peer and key and name:
            aliases.setdefault(key, name)
        key = None
        name = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        match = _NAME_COMMENT_RE.match(line)
        if match:
            value = match.group(1).strip() or None
            if in_peer and key is None:
                name = value
            else:
                pending_name = value
            continue

        if line.startswith("["):
            flush()
            in_peer = line.lower().startswith("[peer]")
            name = pending_name if in_peer else None
            pending_name = None
            continue

        if line.startswith("#") or line.startswith(";"):
            continue

        if in_peer:
            match = _PUBLIC_KEY_RE.match(line)
            if match:
                key = match.group(1)

    flush()
    return aliases


def _apply_aliases(peers):
    """Fill in each peer's operator alias, one config read per interface."""
    cache = {}
    for peer in peers:
        interface = peer["interface"]
        if interface not in cache:
            text = _read_wg_quick_config(interface)
            cache[interface] = _parse_peer_aliases(text) if text else {}
        peer["name"] = cache[interface].get(peer["public_key"])


@debug("wireguard")
def wireguard_metrics():
    """Collect WireGuard interface and peer health.

    Returns one of two outcomes:

    - ``None`` -- COLLECTION FAILURE. Surfaced as ``data["wireguard"] = null``,
      which the server's ``is_a?(Hash)`` dispatch gate skips entirely: no peer
      prune, no auto-resolve of an open ``wireguard_peer_stale`` incident.
    - ``{"interfaces": [...], "peers": [...]}`` -- a successful read. ``peers``
      is the FULL current set, so a peer absent from it is genuinely gone and
      does vanish-prune. ``interfaces`` lists every configured interface even
      when ``peers`` is empty: it is the only source of names for the
      per-interface rollup gauges, which would otherwise vanish from the chart
      instead of reading an honest 0.

    DO NOT add an agent-side cap on ``peers``. It looks like the obvious defense
    for a hub with thousands of roaming clients, but a truncated array is
    indistinguishable from a shrunken one, so the server would vanish-prune
    every peer past the cut. The bound belongs server-side, where it already
    is: ``Ingesters::Wireguard`` caps at MAX_PEERS_PER_TICK, logs which peers
    went unmonitored, and -- crucially -- sets ``safe_to_prune? == false`` for
    that tick so nothing is deleted.
    """
    stdout = _run_wg_dump()
    if stdout is None:
        return None

    interfaces, peers = _parse_dump(stdout, time.time())
    _apply_aliases(peers)
    return {"interfaces": interfaces, "peers": peers}
