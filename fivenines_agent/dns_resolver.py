import dns.exception
import dns.resolver

from fivenines_agent.debug import log

# Lazily-built module resolver with an in-memory cache that honors record TTLs.
# The default dns.resolver.resolve() path has NO cache, so every POST paid a
# fresh DNS round-trip (and up to `lifetime` of latency on a slow resolver).
# Built lazily inside resolve() so a host with a broken resolver config
# surfaces the existing logged failure instead of an import-time crash.
# Forgotten after any failure (_forget_resolver), so the next lookup re-reads
# the system's DNS servers instead of keeping a snapshot that may be wrong.
_resolver = None


def _get_resolver():
    global _resolver
    resolver = _resolver
    if resolver is None:
        resolver = dns.resolver.Resolver()
        resolver.cache = dns.resolver.Cache()
        _resolver = resolver
    # The local, never the global again: the synchronizer, collection and
    # uploader threads share it, and another thread's _forget_resolver() may
    # have reset it since the check.
    return resolver


def _forget_resolver():
    """Drop the resolver: its cache AND its snapshot of the system's DNS servers.

    Resolver() reads the system's DNS servers once. A snapshot taken before the
    network was up stays wrong for good: on Windows, dnspython stores an EMPTY
    server list without complaint (it raises NoResolverConfiguration only for
    an empty resolv.conf), so an agent the SCM started before DHCP had given the
    machine a DNS server failed every lookup at once, with no query sent ("All
    nameservers failed to answer the query ... IN A: " naming no server), until
    the service was restarted. The same holds for servers changed since (a DHCP
    renewal, a VPN). The cache goes with it: dnspython caches NEGATIVE results
    too, and an NXDOMAIN / empty answer with no SOA gets dns.ttl.MAX_TTL (~136
    years), so one captive-portal answer at boot or a single spoofed UDP packet
    would otherwise be served from cache for the life of the process. A failure
    therefore costs one re-read of the system configuration and one fresh
    lookup on the next attempt; only two names ever live in the cache.
    """
    global _resolver
    _resolver = None


class DNSResolver:
    def __init__(self, host):
        self.host = host

    def resolve(self, record_type, timeout=5.0):
        try:
            # Inside the try: Resolver() raises NoResolverConfiguration (a
            # DNSException) when resolv.conf lists no server.
            resolver = _get_resolver()
            return resolver.resolve(self.host, record_type, lifetime=timeout)
        except dns.exception.DNSException as e:
            log(f"DNS error resolving {self.host} {record_type}: {e}")
            _forget_resolver()
            return None
