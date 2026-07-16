import re
import socket

from fivenines_agent.debug import debug, log


# Exact INFO keys shipped as strings. Anything the server encodes into a gauge
# (role master=1, master_link_status up=1, rdb_last_bgsave_status ok=1) stays a
# raw string here -- that mapping is the server's job, not the agent's.
STRING_KEYS = frozenset(
    {
        "redis_version",
        "valkey_version",
        "role",
        "master_link_status",
        "rdb_last_bgsave_status",
    }
)

# Exact INFO keys shipped as floats (existing convention: numeric values go
# through float()). Cumulative counters (keyspace_hits/misses, *_repl_offset,
# total_*) ship raw -- the server derives rates/ratios/ages, not the agent.
NUMERIC_KEYS = frozenset(
    {
        # Currently-shipped fields -- kept byte-compatible.
        "uptime_in_seconds",
        "blocked_clients",
        "connected_clients",
        "evicted_clients",
        "maxclients",
        "total_connections_received",
        "total_commands_processed",
        "evicted_keys",
        "expired_keys",
        # Memory (#491).
        "used_memory",
        "maxmemory",
        "mem_fragmentation_ratio",
        # Stats / perf (#491).
        "instantaneous_ops_per_sec",
        "keyspace_hits",
        "keyspace_misses",
        # Replication (#491).
        "connected_slaves",
        "master_repl_offset",
        "slave_repl_offset",
        "master_last_io_seconds_ago",
        # Persistence (#491).
        "rdb_last_save_time",
        "aof_enabled",
    }
)

# Nested "k=v,k=v" INFO lines: db<N> keyspace stats (all-numeric) and slave<N>
# per-replica lines (mixed -- ip/state are strings). Both parse through the
# same per-value try-float()-fallback-to-string helper.
NESTED_KEY_REGEX = re.compile(r"^(?:db\d+|slave\d+)$")


def _as_float(value):
    """float(value), or None if it is not numeric.

    Returning None (rather than raising) keeps a single malformed line from
    sinking the whole tick's payload: the caller simply drops that one key,
    and a missing key stays missing (the server treats absent as not zero).
    """
    try:
        return float(value)
    except ValueError:
        return None


def _parse_nested(value):
    """Parse a comma-separated k=v INFO value into a dict.

    Numeric sub-values become floats (db<N> keyspace counters, slaveN
    port/offset/lag); non-numeric ones (slaveN ip/state) stay strings. A
    segment without '=' is skipped rather than fatal.
    """
    result = {}
    for pair in value.split(","):
        if "=" not in pair:
            continue
        k, _, v = pair.partition("=")
        num = _as_float(v.strip())
        result[k.strip()] = num if num is not None else v.strip()
    return result


def _parse_info(text):
    """Parse a raw INFO reply into the outgoing metrics dict.

    Cherry-picks exact keys (STRING_KEYS / NUMERIC_KEYS / nested db*/slave*)
    out of the full response. Blank lines, section headers ('# ...'), the RESP
    bulk-length line ('$<n>'), and simple-string / error replies ('+OK',
    '-WRONGPASS ...') carry no ':' key we know, so they are skipped. A single
    unparseable line drops only its own key, never the whole payload.
    """
    metrics = {}
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        # split(':', 1) via partition: slaveN values carry extra ':' (and IPv6
        # ip=::1), so a naive 2-tuple unpack would crash the moment a slaveN
        # line becomes collectable.
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key in STRING_KEYS:
            metrics[key] = value
        elif key in NUMERIC_KEYS:
            num = _as_float(value)
            if num is not None:
                metrics[key] = num
        elif NESTED_KEY_REGEX.match(key):
            metrics[key] = _parse_nested(value)
    return metrics


@debug("redis_metrics")
def redis_metrics(port=6379, password=None):
    try:
        # create_connection handles IPv4/IPv6 address selection.
        s = socket.create_connection(("localhost", int(port)), timeout=5)

        commands = []
        if password:
            commands.append(f"AUTH {password}")
        commands.append("INFO")
        commands.append("QUIT")

        # CRLF-terminated inline commands (RESP inline protocol).
        s.sendall(("\r\n".join(commands) + "\r\n").encode())

        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()

        # A denied/unparseable reply (-WRONGPASS, -NOAUTH) or an empty response
        # yields {} here (no exact key matched); the server's presence gate
        # skips an empty block. A socket/connection error raises and returns
        # None via the except path below.
        return _parse_info(data.decode("utf-8", errors="ignore"))

    except Exception as e:
        log(f"Error collecting Redis metrics: {e}", "error")
