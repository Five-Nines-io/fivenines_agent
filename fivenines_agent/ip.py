import http.client
import ipaddress
import socket
import ssl
import sys
import time
import traceback

import certifi

from fivenines_agent.debug import debug, log
from fivenines_agent.dns_resolver import DNSResolver

# Cache timestamps use CLOCK_BOOTTIME on Linux (counts suspended time) so
# NTP rollback, suspend, and VM restore all advance the clock as expected.
# Falls back to time.monotonic() on platforms without CLOCK_BOOTTIME, which
# is correct for NTP rollback and VM restore but not for suspend.
_ip_v4_cache = {"timestamp": 0, "ip": None, "failures": 0}
_ip_v6_cache = {"timestamp": 0, "ip": None, "failures": 0}


def _now():
    """Monotonic seconds; counts suspend on Linux via CLOCK_BOOTTIME."""
    try:
        return time.clock_gettime(time.CLOCK_BOOTTIME)
    except (AttributeError, OSError):
        return time.monotonic()


# Positive cache: short TTL, just deduplicates calls within a single tick.
POSITIVE_CACHE_TTL = 60

# Negative cache backoff schedule (seconds), indexed by consecutive failure
# count. The first failure deliberately does NOT cache so a single transient
# error (one bad packet, a TLS hiccup, ip.fivenines.io 503) recovers on the
# very next tick without burning a 5 minute window of null payloads. From the
# second consecutive failure onward we back off so a permanently-broken host
# (no IPv6, no driver) stops spamming the journal. See issue #42.
NEGATIVE_BACKOFF_SCHEDULE = (60, 120, 240, 300)

# Maximum length of a response body we will attempt to parse as an IP.
# IPv6 addresses fit in ~45 chars; anything longer is HTML or junk.
MAX_RESPONSE_BODY = 64


def _negative_backoff(failures):
    """How long to suppress retries given the consecutive failure count."""
    if failures <= 1:
        return 0
    idx = min(failures - 2, len(NEGATIVE_BACKOFF_SCHEDULE) - 1)
    return NEGATIVE_BACKOFF_SCHEDULE[idx]


def _is_public_ip(parsed):
    """True if the address is a globally routable public IP.

    Rejects loopback, private (RFC1918 / ULA / CGNAT), link-local, multicast,
    reserved, unspecified, and IPv4-mapped IPv6 addresses. ip.fivenines.io
    returning any of these means the upstream is misconfigured (or hostile);
    we should not cache that as the host's "public IP".

    Uses ipaddress.is_global as the primary discriminator (it correctly
    flags CGNAT, ULA, loopback, doc-prefix, etc as non-global) and adds
    explicit multicast and IPv4-mapped-IPv6 rejections that is_global
    misses.
    """
    if not parsed.is_global:
        return False
    if parsed.is_multicast:
        return False
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return False
    return True


def _validate_ip(body, ipv6):
    """Return body if it parses as a public address of the expected family.

    Length is checked on the encoded BYTE length (not character count) so
    multibyte Unicode whitespace cannot smuggle a valid-looking IP through
    .strip() ("1.2.3.4" + "\u2003" * 57 is 64 chars but 178 bytes). The
    check happens before .strip() so trailing/leading padding is also caught.
    """
    if not body:
        return None
    if len(body.encode("utf-8", errors="replace")) > MAX_RESPONSE_BODY:
        return None
    candidate = body.strip()
    if not candidate:
        return None
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    expected_version = 6 if ipv6 else 4
    if parsed.version != expected_version:
        return None
    if not _is_public_ip(parsed):
        return None
    return candidate


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


def _record_failure(cache):
    """Stamp the cache as failed at the current monotonic time."""
    cache["timestamp"] = _now()
    cache["ip"] = None
    cache["failures"] = cache.get("failures", 0) + 1


@debug("get_ip")
def get_ip(ipv6=False):
    cache = _ip_v6_cache if ipv6 else _ip_v4_cache
    age = _now() - cache["timestamp"]

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
        # Cap the read so a misbehaving (or hostile) upstream cannot force
        # unbounded memory use or log amplification. Reading past the cap is
        # how we detect oversized bodies (otherwise a 1MB body would just look
        # like a 64-byte body via silent truncation).
        raw = response.read(MAX_RESPONSE_BODY * 4)
        if len(raw) > MAX_RESPONSE_BODY:
            log(
                f"ip.fivenines.io returned oversized body ({len(raw)} bytes)",
                "error",
            )
            _record_failure(cache)
            return None
        # Strict UTF-8 decode so non-UTF-8 bytes are not silently dropped.
        try:
            body = raw.decode("utf-8")
        except UnicodeDecodeError:
            log(
                f"ip.fivenines.io returned non-UTF-8 body ({len(raw)} bytes)",
                "error",
            )
            _record_failure(cache)
            return None

        log(f"Status: {response.status}, Reason: {response.reason}", "debug")
        log(f"Response body: {body}", "debug")

        if response.status == 200:
            ip = _validate_ip(body, ipv6=ipv6)
            if ip is None:
                family = "IPv6" if ipv6 else "IPv4"
                log(
                    f"ip.fivenines.io returned non-{family} body: {body[:64]!r}",
                    "error",
                )
                _record_failure(cache)
                return None
            cache["timestamp"] = _now()
            cache["ip"] = ip
            cache["failures"] = 0
            return ip

        _record_failure(cache)
        return None
    except ConnectionError as e:
        log(f"Unexpected error occurred: {e}", "error")
        _record_failure(cache)
        return None

    except Exception as e:
        log(f"Unexpected error occurred: {e}", "error")
        traceback.print_exc(file=sys.stderr)
        _record_failure(cache)
        return None
    finally:
        if conn:
            conn.close()
