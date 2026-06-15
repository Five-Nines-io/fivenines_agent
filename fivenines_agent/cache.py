"""Shared time-to-live cache for metric collectors.

Collectors shell out to expensive CLI commands (smartctl, mdadm, ceph) on a
short interval. This helper caches their results for a TTL so repeated ticks
within the window reuse the last result instead of re-running the command.

Keyed: each logical result has its own key, so one collector can cache several
independent results (e.g. ceph caches per (cluster, command)). Callers with a
single result use a constant key.

Only computed payloads belong in this cache -- never decision/role state. A
caller must not stash "should I run" flags here; cache the command OUTPUT only,
so a stale role can never be served from cache.

Uses time.monotonic(): immune to wall-clock jumps (NTP steps, manual changes),
unlike the time.time() pattern it replaces.
"""

import time


class TTLCache:
    """Per-key time-to-live cache.

    get_or_compute(key, ttl, compute) returns the cached value for key when it
    is younger than ttl seconds, otherwise calls compute() (zero-arg) and stores
    the result.
    """

    def __init__(self):
        # key -> (stored_at_monotonic, value)
        self._entries = {}

    def get_or_compute(self, key, ttl, compute):
        now = time.monotonic()
        entry = self._entries.get(key)
        if entry is not None and (now - entry[0]) < ttl:
            return entry[1]
        value = compute()
        self._entries[key] = (now, value)
        return value
