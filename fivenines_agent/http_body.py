"""Bounded read of a streamed requests response body.

One implementation of the fetch posture the HTTP collectors share (the
inference_metrics/haproxy lineage): the caller issues ``requests.get(...,
stream=True, allow_redirects=False)`` and reads the body through
``read_capped_body``, which enforces BOTH resource bounds a server-pushed URL
needs:

- a BYTE cap, checked while streaming (never buffer-then-check), so a
  misdirected or hostile endpoint cannot grow the long-lived daemon's RSS
  without bound;
- a WALL-CLOCK deadline, because ``requests``' scalar ``timeout`` is a
  per-socket-operation inactivity timeout: an endpoint trickling one byte
  every few seconds never trips it, and at that rate a byte cap alone takes
  hours to fire -- on the watchdog-bounded collection loop that is a
  fleet-restart DoS, not a slow read.

Raises ``BodyOverBudget`` (a ValueError) when either bound is hit; callers map
that onto their module's existing failure contract. The response is closed on
every path.
"""

import time

# Matches the chunk size the pre-existing readers use (_RECV_CHUNK_BYTES in
# inference_metrics.py / haproxy.py).
_RECV_CHUNK_BYTES = 64 * 1024


class BodyOverBudget(ValueError):
    """The response body exceeded the byte cap or the read deadline."""


def read_capped_body(response, max_bytes, timeout_s):
    """Stream *response*'s body under *max_bytes* and *timeout_s*; bytes out.

    Returns the raw body bytes. Raises BodyOverBudget when either bound is
    exceeded; any other read error propagates for the caller's transport
    handling. Closes the response on every path.
    """
    deadline = time.monotonic() + timeout_s
    chunks = bytearray()
    try:
        for chunk in response.iter_content(chunk_size=_RECV_CHUNK_BYTES):
            if time.monotonic() > deadline:
                raise BodyOverBudget(
                    f"response body read exceeded {timeout_s}s deadline"
                )
            if not chunk:
                continue
            chunks += chunk
            if len(chunks) > max_bytes:
                raise BodyOverBudget(
                    f"response body exceeded {max_bytes} bytes"
                )
    finally:
        response.close()
    return bytes(chunks)
