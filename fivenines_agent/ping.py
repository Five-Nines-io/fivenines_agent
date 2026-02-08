"""TCP ping utility for latency measurement."""

import socket
import time

from fivenines_agent.debug import debug


@debug("tcp_ping")
def tcp_ping(host, port=80, timeout=5):
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout):
            return (time.time() - start) * 1000
    except Exception:
        return None
