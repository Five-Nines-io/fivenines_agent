import dns.exception
import dns.resolver

from fivenines_agent.debug import log

# Lazily-built module resolver with an in-memory cache that honors record TTLs.
# The default dns.resolver.resolve() path has NO cache, so every POST paid a
# fresh DNS round-trip (and up to `lifetime` of latency on a slow resolver).
# Built lazily inside resolve() so a host with a broken resolver config
# surfaces the existing logged failure instead of an import-time crash.
_resolver = None


def _get_resolver():
    global _resolver
    if _resolver is None:
        resolver = dns.resolver.Resolver()
        resolver.cache = dns.resolver.Cache()
        _resolver = resolver
    return _resolver


class DNSResolver:
    def __init__(self, host):
        self.host = host

    def resolve(self, record_type, timeout=5.0):
        resolver = _get_resolver()
        try:
            return resolver.resolve(self.host, record_type, lifetime=timeout)
        except dns.exception.DNSException as e:
            log(f"DNS error resolving {self.host} {record_type}: {e}")
            # Flush the cache on ANY failure. dnspython caches NEGATIVE
            # results too, and an NXDOMAIN / empty answer with no SOA gets
            # dns.ttl.MAX_TTL (~136 years): one captive-portal answer at boot
            # or a single spoofed UDP packet would otherwise pin the failure
            # in the process-lifetime cache and silence the agent until a
            # manual restart -- every retry would fail instantly from cache
            # with zero network I/O. Flushing keeps positive caching (the
            # whole point) while making a failure cost at most one extra
            # lookup on the next attempt. Only two names ever live here.
            try:
                if resolver.cache is not None:
                    resolver.cache.flush()
            except Exception:
                pass
            return None
