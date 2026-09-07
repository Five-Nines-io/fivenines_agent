"""Tests for the cached DNS resolver seam."""

from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver

import fivenines_agent.dns_resolver as dns_resolver_module
from fivenines_agent.dns_resolver import DNSResolver, _get_resolver


def test_get_resolver_is_memoized_and_has_a_cache():
    """One Resolver per process, with a TTL-honoring cache attached -- the
    whole point: the default resolve() path re-queried DNS on every POST."""
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


def test_resolve_flushes_cache_on_failure():
    """A DNS failure must flush the resolver cache: dnspython caches NEGATIVE
    results too, and an NXDOMAIN with no SOA gets a ~136-year TTL -- one bad
    answer (captive portal, spoofed packet) would otherwise be served from
    cache forever and silence the agent until restart."""
    fake = MagicMock()
    fake.resolve.side_effect = dns.exception.DNSException("nxdomain")
    with patch.object(dns_resolver_module, "_get_resolver", return_value=fake):
        assert DNSResolver("api.example.org").resolve("A") is None
    fake.cache.flush.assert_called_once()


def test_resolve_failure_survives_flush_error():
    fake = MagicMock()
    fake.resolve.side_effect = dns.exception.DNSException("timeout")
    fake.cache.flush.side_effect = RuntimeError("no cache")
    with patch.object(dns_resolver_module, "_get_resolver", return_value=fake):
        assert DNSResolver("api.example.org").resolve("A") is None
