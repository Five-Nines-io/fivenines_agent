"""Tests for Brique C: continuous per-tick log signals.

Pure: _signals_for_unit is tested directly; collect_log_signals injects the
entries seam and the clock. No real journald.
"""

from fivenines_agent import logs

# --- _signals_for_unit ---


def test_signals_counts_groups_and_drops_info():
    entries = [
        {"priority": "3", "message": "timeout 1s"},
        {"priority": "3", "message": "timeout 2s"},  # same fp as above
        {"priority": "4", "message": "slow query"},
        {"priority": "6", "message": "all good"},  # info: dropped
    ]
    out = logs._signals_for_unit(entries)
    assert out["error_rate"] == 2
    assert out["warn_rate"] == 1
    timeout = [f for f in out["fingerprints"] if f["count"] == 2][0]
    assert timeout["severity"] == "error"


def test_signals_sample_is_redacted():
    out = logs._signals_for_unit([{"priority": "3", "message": "token=sk_live_1 boom"}])
    assert "sk_live_1" not in out["fingerprints"][0]["sample"]


def test_signals_severity_escalates_within_group():
    entries = [
        {"priority": "4", "message": "db slow shard 1"},
        {"priority": "3", "message": "db slow shard 2"},
    ]
    out = logs._signals_for_unit(entries)
    assert out["fingerprints"][0]["severity"] == "error"
    assert out["fingerprints"][0]["count"] == 2
    assert out["error_rate"] == 1 and out["warn_rate"] == 1


def test_signals_top_fingerprints_capped():
    entries = [{"priority": "3", "message": f"err {chr(65 + i)}"} for i in range(30)]
    out = logs._signals_for_unit(entries)
    assert len(out["fingerprints"]) == logs._TOP_FINGERPRINTS


# --- collect_log_signals ---


def test_collect_units_none_is_empty():
    assert logs.collect_log_signals(units=None, _now=lambda: 1000) == {
        "window_s": 60,
        "units": {},
    }


def test_collect_disabled_is_empty():
    out = logs.collect_log_signals(
        units=["a.service"], enabled=False, _now=lambda: 1000
    )
    assert out["units"] == {}


def test_collect_window_clamping():
    seen = {}

    def fake(unit, since, lines, timeout=None):
        seen["since"] = since
        return []

    logs.collect_log_signals(
        units=["a"], signal_interval_s=30, _entries_fn=fake, _now=lambda: 1000
    )
    assert seen["since"] == 970  # 1000 - 30
    for bad in ("x", True, 0, -5):
        logs.collect_log_signals(
            units=["a"], signal_interval_s=bad, _entries_fn=fake, _now=lambda: 1000
        )
        assert seen["since"] == 940  # clamped to 60 -> 1000 - 60


def test_collect_per_unit_isolation():
    def fake(unit, since, lines, timeout=None):
        if unit == "bad":
            raise RuntimeError("boom")
        return [{"priority": "3", "message": "e"}]

    out = logs.collect_log_signals(
        units=["bad", "good"], _entries_fn=fake, _now=lambda: 1000
    )
    assert "good" in out["units"] and "bad" not in out["units"]


def test_collect_skips_unit_on_capture_failure():
    def fake(unit, since, lines, timeout=None):
        return None if unit == "x" else [{"priority": "3", "message": "e"}]

    out = logs.collect_log_signals(
        units=["x", "y"], _entries_fn=fake, _now=lambda: 1000
    )
    assert list(out["units"].keys()) == ["y"]


def test_collect_uses_short_signal_timeout():
    # Signals use a short timeout (A6) - distinct from the 30s capture timeout -
    # so N units x a low incident interval cannot starve the systemd watchdog.
    seen = {}

    def fake(unit, since, lines, timeout=None):
        seen["timeout"] = timeout
        return []

    logs.collect_log_signals(units=["a"], _entries_fn=fake, _now=lambda: 1000)
    assert seen["timeout"] == logs._SIGNAL_TIMEOUT == 5


def test_collect_caps_units_per_tick_and_warns_once():
    # An oversized backend allowlist is capped so N sequential journalctl calls
    # on the main loop can't exceed the systemd watchdog and self-restart.
    logs._signal_units_capped_warned = False  # reset module-level warn-once flag
    seen = []

    def fake(unit, since, lines, timeout=None):
        seen.append(unit)
        return [{"priority": "3", "message": "e"}]

    many = [f"u{i}.service" for i in range(20)]
    out = logs.collect_log_signals(units=many, _entries_fn=fake, _now=lambda: 1000)
    assert len(seen) == logs._MAX_SIGNAL_UNITS  # only the first N scanned
    assert len(out["units"]) == logs._MAX_SIGNAL_UNITS
    assert logs._signal_units_capped_warned is True


def test_collect_absorbs_extra_config_kwargs():
    # posture / redaction come from the logs config block; must not break the call.
    out = logs.collect_log_signals(
        units=[], posture="digest", redaction={"version": 1}, _now=lambda: 1000
    )
    assert out == {"window_s": 60, "units": {}}
