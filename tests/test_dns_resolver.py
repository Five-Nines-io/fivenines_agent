"""Tests for the cached DNS resolver seam."""

import sys
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver

import fivenines_agent.dns_resolver as dns_resolver_module
from fivenines_agent.dns_resolver import DNSResolver, _get_resolver


def test_get_resolver_is_memoized_and_has_a_cache():
    """One Resolver until a lookup fails (resolve() then forgets it), with a
    TTL-honoring cache attached -- the whole point: the default resolve() path
    re-queried DNS on every POST."""
    with patch.object(dns_resolver_module.dns.resolver, "Resolver") as resolver_cls:
        instance = MagicMock()
        resolver_cls.return_value = instance
        first = _get_resolver()
        second = _get_resolver()
    assert first is second is instance
    resolver_cls.assert_called_once()
    # A REAL cache object was attached (dns.resolver.Cache honors record
    # TTLs). isinstance, not `is not None`: on a MagicMock instance any
    # attribute access is truthy, so a weaker assertion could never fail.
    assert isinstance(instance.cache, dns.resolver.Cache)


# Value: protects=_get_resolver never hands a thread None while another thread forgets the shared resolver; fails_when=it returns the module global again after its check, so a concurrent _forget_resolver() makes resolve() raise AttributeError (not a DNSException) on the synchronizer, collection or uploader thread; why_new=no test interleaves a forget with a get, and before this change nothing ever reset the global; seam=none; no_claim=real thread scheduling (the interleaving is forced with sys.settrace at the return line)
def test_get_resolver_survives_a_concurrent_forget():
    code = _get_resolver.__code__
    return_line = max(line for _, _, line in code.co_lines() if line)

    def tracer(frame, event, arg):
        if frame.f_code is not code:
            return None

        def local(frame, event, arg):
            if event == "line" and frame.f_lineno == return_line:
                dns_resolver_module._forget_resolver()  # the other thread
            return local

        return local

    held = MagicMock()
    dns_resolver_module._resolver = held
    with patch.object(dns_resolver_module.dns.resolver, "Resolver") as resolver_cls:
        previous = sys.gettrace()
        sys.settrace(tracer)
        try:
            memoized = _get_resolver()
            built = _get_resolver()
        finally:
            sys.settrace(previous)
    assert memoized is held
    # The forget left the global None, so the second call built a resolver,
    # and the forget that hit it before its return must not lose it either.
    assert built is resolver_cls.return_value
    assert dns_resolver_module._resolver is None


def test_resolve_delegates_with_lifetime():
    fake = MagicMock()
    fake.resolve.return_value = ["answer"]
    with patch.object(dns_resolver_module, "_get_resolver", return_value=fake):
        assert DNSResolver("api.example.org").resolve("A", timeout=2.5) == ["answer"]
    fake.resolve.assert_called_once_with("api.example.org", "A", lifetime=2.5)


def test_resolve_returns_none_on_dns_exception():
    fake = MagicMock()
    fake.resolve.side_effect = dns.exception.DNSException("nxdomain")
    with patch.object(dns_resolver_module, "_get_resolver", return_value=fake):
        assert DNSResolver("api.example.org").resolve("AAAA") is None


def test_resolve_forgets_the_resolver_on_failure():
    """A DNS failure drops the resolver, cache included: dnspython caches
    NEGATIVE results too, and an NXDOMAIN with no SOA gets a ~136-year TTL --
    one bad answer (captive portal, spoofed packet) would otherwise be served
    from cache forever and silence the agent until restart. The next lookup
    builds a fresh one, with an empty cache and the system's current servers."""
    failing = MagicMock()
    failing.resolve.side_effect = dns.exception.DNSException("nxdomain")
    fresh = MagicMock()
    fresh.resolve.return_value = ["answer"]
    with patch.object(
        dns_resolver_module.dns.resolver, "Resolver", side_effect=[failing, fresh]
    ) as resolver_cls:
        assert DNSResolver("api.example.org").resolve("A") is None
        assert dns_resolver_module._resolver is None
        assert DNSResolver("api.example.org").resolve("A") == ["answer"]
    assert resolver_cls.call_count == 2
    assert isinstance(fresh.cache, dns.resolver.Cache)


def _resolver_with_servers(nameservers):
    """A real dnspython Resolver whose system configuration listed these
    servers (configure=False: the test host's resolv.conf is not read)."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = nameservers
    return resolver


def test_resolve_recovers_from_an_empty_server_list_read_at_start():
    """The Windows boot race: the service starts before DHCP has given the
    machine a DNS server, and dnspython's Windows configuration read stores
    an EMPTY server list without raising. Every lookup then fails at once with
    no query sent -- the real message names no server -- and the agent stayed
    offline until a restart, the snapshot being kept for the process's life.
    Once the system lists a server, the next lookup must use it."""
    answering = MagicMock()
    answering.resolve.return_value = ["192.0.2.10"]
    with patch.object(
        dns_resolver_module.dns.resolver,
        "Resolver",
        side_effect=[_resolver_with_servers([]), answering],
    ), patch.object(dns_resolver_module, "log") as log:
        assert DNSResolver("api.example.org").resolve("A") is None
        assert DNSResolver("api.example.org").resolve("A") == ["192.0.2.10"]
    # The line seen on the affected host: dnspython's own NoNameservers text,
    # ending where the list of the servers tried would be.
    log.assert_called_once()
    message = log.call_args.args[0]
    assert (
        "All nameservers failed to answer the query api.example.org. IN A: " in message
    )
    assert message.endswith("IN A: ")
    answering.resolve.assert_called_once_with("api.example.org", "A", lifetime=5.0)


def test_resolve_survives_a_server_list_that_cannot_be_read():
    """Resolver() itself raises NoResolverConfiguration when resolv.conf lists
    no server: a logged failure, never an exception, and nothing memoized."""
    with patch.object(
        dns_resolver_module.dns.resolver,
        "Resolver",
        side_effect=dns.resolver.NoResolverConfiguration("no nameservers"),
    ):
        assert DNSResolver("api.example.org").resolve("A") is None
    assert dns_resolver_module._resolver is None
