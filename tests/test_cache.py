from fivenines_agent import cache as cache_mod


class _FakeClock:
    """Controllable monotonic clock for deterministic TTL tests."""

    def __init__(self, start=1000.0):
        self.t = start

    def monotonic(self):
        return self.t


def test_miss_computes_and_stores(monkeypatch):
    clock = _FakeClock()
    monkeypatch.setattr(cache_mod, "time", clock)
    cache = cache_mod.TTLCache()
    calls = []

    def compute():
        calls.append(1)
        return "v1"

    assert cache.get_or_compute("k", 60, compute) == "v1"
    assert calls == [1]


def test_hit_within_ttl_returns_cached_without_recompute(monkeypatch):
    clock = _FakeClock()
    monkeypatch.setattr(cache_mod, "time", clock)
    cache = cache_mod.TTLCache()
    calls = []

    def compute():
        calls.append(1)
        return "v1"

    assert cache.get_or_compute("k", 60, compute) == "v1"
    clock.t += 59  # still inside the TTL window
    assert cache.get_or_compute("k", 60, lambda: "should-not-run") == "v1"
    assert calls == [1]


def test_stale_at_ttl_boundary_recomputes(monkeypatch):
    clock = _FakeClock()
    monkeypatch.setattr(cache_mod, "time", clock)
    cache = cache_mod.TTLCache()
    values = iter(["v1", "v2"])

    def compute():
        return next(values)

    assert cache.get_or_compute("k", 60, compute) == "v1"
    clock.t += 60  # elapsed == ttl, not < ttl, so recompute
    assert cache.get_or_compute("k", 60, compute) == "v2"


def test_distinct_keys_are_independent(monkeypatch):
    clock = _FakeClock()
    monkeypatch.setattr(cache_mod, "time", clock)
    cache = cache_mod.TTLCache()

    assert cache.get_or_compute("a", 60, lambda: "A") == "A"
    assert cache.get_or_compute("b", 60, lambda: "B") == "B"
    # Each key keeps its own value; neither overwrites the other.
    assert cache.get_or_compute("a", 60, lambda: "x") == "A"
    assert cache.get_or_compute("b", 60, lambda: "x") == "B"
