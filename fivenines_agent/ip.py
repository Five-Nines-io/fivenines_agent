import http.client
import socket
import ssl
import sys
import time
import traceback

import certifi

from fivenines_agent.debug import debug, log
from fivenines_agent.dns_resolver import DNSResolver

_ip_v4_cache = {"timestamp": 0, "ip": None, "failures": 0}
_ip_v6_cache = {"timestamp": 0, "ip": None, "failures": 0}

# Positive cache: short TTL, just deduplicates calls within a single tick.
POSITIVE_CACHE_TTL = 60

# Negative cache backoff schedule (seconds), indexed by consecutive failure
# count. The first failure deliberately does NOT cache so a single transient
# error (one bad packet, a TLS hiccup, ip.fivenines.io 503) recovers on the
# very next tick without burning a 5 minute window of null payloads. From the
# second consecutive failure onward we back off so a permanently-broken host
# (no IPv6, no driver) stops spamming the journal. See issue #42.
NEGATIVE_BACKOFF_SCHEDULE = (60, 120, 240, 300)


def _negative_backoff(failures):
    """How long to suppress retries given the consecutive failure count."""
    if failures <= 1:
        return 0
    idx = min(failures - 2, len(NEGATIVE_BACKOFF_SCHEDULE) - 1)
    return NEGATIVE_BACKOFF_SCHEDULE[idx]


class CustomHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port=None, ipv6=False, timeout=5, **kwargs):
        super().__init__(host, port, timeout=timeout, **kwargs)
        self.ipv6 = ipv6
        self.timeout = timeout

    def connect(self):
        resolver = DNSResolver(self.host)
        record_type = "AAAA" if self.ipv6 else "A"
        try:
            answers = resolver.resolve(record_type)
            if not answers:
                raise ConnectionError(
                    f"No DNS records found for {self.host} ({record_type})"
                )
        except Exception as e:
            raise ConnectionError(f"DNS resolution failed for {self.host}: {e}")

        for rdata in answers:
            ip = rdata.address
            af = socket.AF_INET6 if self.ipv6 else socket.AF_INET
            try:
                self.sock = socket.socket(af, socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                self.sock.connect((ip, self.port))
                self.sock = self._context.wrap_socket(
                    self.sock, server_hostname=self.host
                )
                return
            except OSError as e:
                if self.sock:
                    self.sock.close()
                log(f"Could not connect to {ip}: {e}", "error")
                continue  # Try next IP

        raise ConnectionError(
            f"Could not connect to {self.host} on port {self.port} with family {'IPv6' if self.ipv6 else 'IPv4'}"
        )


def _record_failure(cache, now):
    cache["timestamp"] = now
    cache["ip"] = None
    cache["failures"] = cache.get("failures", 0) + 1


@debug("get_ip")
def get_ip(ipv6=False):
    now = time.time()
    cache = _ip_v6_cache if ipv6 else _ip_v4_cache
    age = now - cache["timestamp"]

    # Positive cache: short TTL, return the previously-fetched IP.
    if cache["ip"] is not None and age < POSITIVE_CACHE_TTL:
        return cache["ip"]

    # Negative cache: kicks in only after >=2 consecutive failures, with TTL
    # growing per the backoff schedule. The first failure falls through and
    # retries on the next call so transients self-heal in one tick.
    backoff = _negative_backoff(cache.get("failures", 0))
    if cache["ip"] is None and backoff > 0 and age < backoff:
        return None

    conn = None
    try:
        ssl_context = ssl.create_default_context(cafile=certifi.where())

        conn = CustomHTTPSConnection("ip.fivenines.io", ipv6=ipv6, context=ssl_context)
        conn.request("GET", "")
        response = conn.getresponse()
        body = response.read().decode("utf-8")

        log(f"Status: {response.status}, Reason: {response.reason}", "debug")
        log(f"Response body: {body}", "debug")

        if response.status == 200:
            ip = body.strip()
            cache["timestamp"] = now
            cache["ip"] = ip
            cache["failures"] = 0
            return ip

        _record_failure(cache, now)
        return None
    except ConnectionError as e:
        log(f"Unexpected error occurred: {e}", "error")
        _record_failure(cache, now)
        return None

    except Exception as e:
        log(f"Unexpected error occurred: {e}", "error")
        traceback.print_exc(file=sys.stderr)
        _record_failure(cache, now)
        return None
    finally:
        if conn:
            conn.close()
