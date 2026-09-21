"""Tests for the operator's local journal allowlist (journal_units.allow).

The file is the host owner's veto over which unit journals the agent may read
at all. Two properties matter most and are tested from both ends: an absent
file changes nothing (the default install), and a file that exists but cannot
be honoured denies everything rather than silently reading as "no policy".
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from fivenines_agent import journal_policy, log_capture, logs, systemd


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFIG_DIR", str(tmp_path))
    journal_policy.reset_cache()
    yield tmp_path
    journal_policy.reset_cache()


def write_allowlist(config_dir, content):
    path = config_dir / journal_policy.ALLOWLIST_FILENAME
    path.write_text(content)
    journal_policy.reset_cache()
    return path


# --- no file: the default install is untouched ---


def test_absent_file_allows_everything(config_dir):
    assert journal_policy.unit_allowed("anything.service") is True
    assert journal_policy.filter_units(["a.service", "b.socket"]) == (
        ["a.service", "b.socket"],
        [],
    )


# --- a file in force ---


def test_listed_units_are_allowed_and_others_refused(config_dir):
    write_allowlist(config_dir, "nginx.service\npostgresql.service\n")
    assert journal_policy.unit_allowed("nginx.service") is True
    assert journal_policy.unit_allowed("mysql.service") is False


def test_implicit_service_suffix_matches_from_either_side(config_dir):
    """systemd's own shorthand: `journalctl -u nginx` means nginx.service."""
    write_allowlist(config_dir, "nginx\n")
    assert journal_policy.unit_allowed("nginx.service") is True
    assert journal_policy.unit_allowed("nginx") is True

    write_allowlist(config_dir, "redis.service\n")
    assert journal_policy.unit_allowed("redis") is True


def test_non_service_units_keep_their_own_suffix(config_dir):
    write_allowlist(config_dir, "docker.socket\n")
    assert journal_policy.unit_allowed("docker.socket") is True
    assert journal_policy.unit_allowed("docker.service") is False


def test_globs_are_supported(config_dir):
    write_allowlist(config_dir, "postgresql@*.service\napp-*\n")
    assert journal_policy.unit_allowed("postgresql@14-main.service") is True
    assert journal_policy.unit_allowed("app-web.service") is True
    assert journal_policy.unit_allowed("nginx.service") is False


def test_a_bare_glob_is_not_narrowed_to_services(config_dir):
    """'*' means every unit. Appending the implicit .service to a pattern
    would silently turn it into '*.service' and refuse every socket/timer."""
    write_allowlist(config_dir, "*\n")
    assert journal_policy.unit_allowed("docker.socket") is True
    assert journal_policy.unit_allowed("nginx.service") is True

    write_allowlist(config_dir, "app-*\n")
    assert journal_policy.unit_allowed("app-web.timer") is True


def test_matching_is_case_sensitive_on_every_platform(config_dir):
    """systemd unit names are case-sensitive. fnmatch (rather than
    fnmatchcase) lowercases both sides on Windows, where this suite also
    runs -- that would widen an operator's policy on one platform only."""
    write_allowlist(config_dir, "nginx.service\n")
    assert journal_policy.unit_allowed("nginx.service") is True
    assert journal_policy.unit_allowed("NGINX.service") is False


def test_comments_and_blank_lines_are_ignored(config_dir):
    write_allowlist(
        config_dir,
        "# only the web tier\n\n   \nnginx.service\n  # trailing comment line\n",
    )
    assert journal_policy.unit_allowed("nginx.service") is True
    assert journal_policy.unit_allowed("mysql.service") is False


def test_empty_file_denies_everything(config_dir):
    """An empty allowlist is a statement ('read nothing'), not an absent one."""
    write_allowlist(config_dir, "# nothing allowed\n")
    assert journal_policy.unit_allowed("nginx.service") is False
    assert journal_policy.filter_units(["nginx.service"]) == ([], ["nginx.service"])


def test_non_string_or_empty_units_are_refused_under_a_policy(config_dir):
    write_allowlist(config_dir, "nginx.service\n")
    assert journal_policy.unit_allowed(None) is False
    assert journal_policy.unit_allowed(42) is False
    assert journal_policy.unit_allowed("") is False
    assert journal_policy.unit_allowed("   ") is False


# --- bounds on an operator-written file ---


def test_pattern_count_is_bounded(config_dir):
    lines = "\n".join(
        f"unit-{i}.service" for i in range(journal_policy.MAX_PATTERNS + 50)
    )
    write_allowlist(config_dir, lines)
    assert journal_policy.unit_allowed("unit-0.service") is True
    assert (
        journal_policy.unit_allowed(f"unit-{journal_policy.MAX_PATTERNS + 10}.service")
        is False
    )


def test_pattern_count_bound_is_exact(config_dir):
    n = journal_policy.MAX_PATTERNS
    write_allowlist(config_dir, "\n".join(f"unit-{i}.service" for i in range(n + 50)))
    assert journal_policy.unit_allowed(f"unit-{n - 1}.service") is True
    assert journal_policy.unit_allowed(f"unit-{n}.service") is False


def test_a_line_of_exactly_max_chars_is_kept(config_dir):
    name = "u" * (journal_policy.MAX_PATTERN_CHARS - len(".service")) + ".service"
    assert len(name) == journal_policy.MAX_PATTERN_CHARS
    write_allowlist(config_dir, name + "\n")
    assert journal_policy.unit_allowed(name) is True


def test_pattern_overflow_is_reported(config_dir):
    """Everything past the cap is DENIED, so it can never be silent."""
    n = journal_policy.MAX_PATTERNS
    write_allowlist(config_dir, "\n".join(f"unit-{i}.service" for i in range(n + 5)))
    with patch("fivenines_agent.journal_policy.log") as mock_log:
        journal_policy.unit_allowed("unit-0.service")
    messages = [c.args[0] for c in mock_log.call_args_list if c.args[1] == "error"]
    assert any("only the first" in m for m in messages)


def test_a_file_at_exactly_the_cap_is_not_reported_as_overflowing(config_dir):
    """A complete file is not a truncated one; a permanent error line about
    units that were never dropped sends operators chasing nothing."""
    n = journal_policy.MAX_PATTERNS
    write_allowlist(config_dir, "\n".join(f"unit-{i}.service" for i in range(n)))
    with patch("fivenines_agent.journal_policy.log") as mock_log:
        journal_policy.unit_allowed("unit-0.service")
    messages = [c.args[0] for c in mock_log.call_args_list if c.args[1] == "error"]
    assert not any("only the first" in m for m in messages)


def test_an_oversized_file_is_refused_not_truncated(config_dir):
    """Cutting the blob at a byte offset can leave a partial last line, and
    `*.service` cut to `*` would WIDEN the policy to every unit."""
    path = config_dir / journal_policy.ALLOWLIST_FILENAME
    padding = "# " + "p" * 120 + "\n"
    blob = padding * (journal_policy.MAX_FILE_BYTES // len(padding) + 1)
    path.write_text(blob + "*.service\n")
    journal_policy.reset_cache()
    with patch("fivenines_agent.journal_policy.log") as mock_log:
        assert journal_policy.unit_allowed("nginx.service") is False
        assert journal_policy.unit_allowed("docker.socket") is False
    messages = [c.args[0] for c in mock_log.call_args_list if c.args[1] == "error"]
    assert any("refusing every journal read" in m for m in messages)


def test_a_server_supplied_glob_is_refused(config_dir):
    """journalctl -u expands globs. Matching one literally against an
    operator pattern walks straight through the veto."""
    write_allowlist(config_dir, "app-?.service\n")
    assert journal_policy.unit_allowed("app-a.service") is True
    assert journal_policy.unit_allowed("app-*.service") is False
    assert journal_policy.unit_allowed("app-[ab].service") is False
    allowed, refused = journal_policy.filter_units(["app-a.service", "app-*.service"])
    assert allowed == ["app-a.service"]
    assert refused == ["app-*.service"]


def test_a_path_form_unit_is_refused(config_dir):
    """`journalctl -u /var/log` resolves to var-log.mount, but the policy
    would be checking the text `/var/log` -- a different string than the one
    journalctl reads, which is exactly how a veto gets walked through."""
    write_allowlist(config_dir, "*.service\n")
    assert journal_policy.unit_allowed("nginx.service") is True
    assert journal_policy.unit_allowed("/var/log") is False
    assert journal_policy.unit_allowed("/etc/systemd/system/x.service") is False
    # ...and the unit that path really names is refused either way.
    assert journal_policy.unit_allowed("var-log.mount") is False


def test_an_option_form_unit_is_refused(config_dir):
    """A name starting with a dash would be parsed by journalctl as an
    option, not as the argument to -u."""
    write_allowlist(config_dir, "*\n")
    assert journal_policy.unit_allowed("--output=cat") is False
    assert journal_policy.unit_allowed("-n") is False


def test_an_over_long_unit_name_is_refused(config_dir):
    write_allowlist(config_dir, "*\n")
    assert journal_policy.unit_allowed("u" * journal_policy.MAX_UNIT_CHARS) is True
    assert (
        journal_policy.unit_allowed("u" * (journal_policy.MAX_UNIT_CHARS + 1)) is False
    )


def test_a_dangling_symlink_denies_rather_than_disappearing(config_dir):
    """A policy that points at a missing target is a broken policy, not an
    absent one."""
    path = config_dir / journal_policy.ALLOWLIST_FILENAME
    path.symlink_to(config_dir / "does-not-exist")
    journal_policy.reset_cache()
    with patch("fivenines_agent.journal_policy.log"):
        assert journal_policy.unit_allowed("nginx.service") is False


@pytest.mark.skipif(
    not hasattr(os, "mkfifo"),
    reason="os.mkfifo is Unix-only; Windows CI runs this suite",
)
def test_a_non_regular_policy_file_is_refused(config_dir):
    """open() on a FIFO with no writer blocks forever, which on the
    collection loop is a watchdog kill."""
    path = config_dir / journal_policy.ALLOWLIST_FILENAME
    os.mkfifo(str(path))
    journal_policy.reset_cache()
    with patch("fivenines_agent.journal_policy.log"):
        assert journal_policy.unit_allowed("nginx.service") is False


def test_a_mode_change_invalidates_the_cached_decision(config_dir):
    """chmod changes neither mtime, size nor inode: without st_mode in the
    key, fixing a 0600 policy would leave the refusal cached forever."""
    path = write_allowlist(config_dir, "nginx.service\n")
    assert journal_policy.unit_allowed("nginx.service") is True
    path.chmod(0o600)
    with patch("fivenines_agent.journal_policy.log"):
        # Same content, new mode -> the policy is re-read rather than served
        # from the cache. (Readable as the owner here, so it still allows.)
        assert journal_policy.unit_allowed("nginx.service") is True
    assert journal_policy._cache["key"][5] == os.stat(str(path)).st_mode


def test_the_server_unit_list_is_bounded(config_dir):
    """The server sends this list and nothing else bounds it."""
    write_allowlist(config_dir, "*\n")
    units = [f"u{i}.service" for i in range(journal_policy.MAX_FILTER_UNITS + 50)]
    allowed, refused = journal_policy.filter_units(units)
    assert len(allowed) == journal_policy.MAX_FILTER_UNITS
    assert len(refused) == 50


def test_over_long_lines_are_dropped_and_reported(config_dir):
    long_line = "x" * (journal_policy.MAX_PATTERN_CHARS + 1)
    write_allowlist(config_dir, f"{long_line}\nnginx.service\n")
    with patch("fivenines_agent.journal_policy.log") as mock_log:
        assert journal_policy.unit_allowed("nginx.service") is True
    messages = [c.args[0] for c in mock_log.call_args_list]
    assert any("over-long" in m for m in messages)


# --- a policy that cannot be honoured must deny, not disappear ---


def test_unstattable_file_denies_everything(config_dir):
    with patch(
        "fivenines_agent.journal_policy.os.stat", side_effect=PermissionError("nope")
    ):
        with patch("fivenines_agent.journal_policy.log") as mock_log:
            assert journal_policy.unit_allowed("nginx.service") is False
            assert journal_policy.unit_allowed("nginx.service") is False
    errors = [c for c in mock_log.call_args_list if c.args[1] == "error"]
    assert len(errors) == 1  # warned once, not once per read


def test_unreadable_file_denies_everything(config_dir):
    write_allowlist(config_dir, "nginx.service\n")
    with patch("builtins.open", side_effect=PermissionError("denied")):
        with patch("fivenines_agent.journal_policy.log") as mock_log:
            assert journal_policy.unit_allowed("nginx.service") is False
    errors = [c for c in mock_log.call_args_list if c.args[1] == "error"]
    assert len(errors) == 1


def test_an_undecodable_file_still_applies_its_readable_patterns(config_dir):
    """A stray byte must not take log monitoring down, nor widen the policy."""
    path = config_dir / journal_policy.ALLOWLIST_FILENAME
    path.write_bytes(b"nginx.service\nmy\xffunit.service\n")
    journal_policy.reset_cache()
    assert journal_policy.unit_allowed("nginx.service") is True
    assert journal_policy.unit_allowed("myunit.service") is False


def test_a_read_that_raises_denies_everything(config_dir):
    """Any failure reading an operator-written file denies, never raises."""
    write_allowlist(config_dir, "nginx.service\n")
    with patch("builtins.open", side_effect=RuntimeError("something odd")):
        with patch("fivenines_agent.journal_policy.log"):
            assert journal_policy.unit_allowed("nginx.service") is False


def test_a_clean_read_rearms_the_warning(config_dir):
    """A permission problem that is fixed and then reappears is reported again.

    Driven entirely through the file: calling reset_cache() here would clear
    the warning latch itself and prove nothing about the production line that
    is supposed to clear it.
    """
    path = write_allowlist(config_dir, "nginx.service\n")
    with patch("builtins.open", side_effect=PermissionError("denied")):
        with patch("fivenines_agent.journal_policy.log") as mock_log:
            journal_policy.unit_allowed("nginx.service")
    assert len([c for c in mock_log.call_args_list if c.args[1] == "error"]) == 1

    # Fixed: a clean read must clear the latch on its own (new size -> new
    # stat identity, so the cache re-reads without any help from the test).
    path.write_text("nginx.service\nredis.service\n")
    assert journal_policy.unit_allowed("redis.service") is True

    # Broken again -> reported again.
    path.write_text("nginx.service\nredis.service\nmysql.service\n")
    with patch("builtins.open", side_effect=PermissionError("denied")):
        with patch("fivenines_agent.journal_policy.log") as mock_log:
            journal_policy.unit_allowed("nginx.service")
    assert len([c for c in mock_log.call_args_list if c.args[1] == "error"]) == 1


def test_an_unreadable_file_is_only_opened_once_per_change(config_dir):
    """The deny is cached: a 0600 root-owned file must not be re-opened once
    per unit per tick."""
    write_allowlist(config_dir, "nginx.service\n")
    opens = []

    def counting_open(path, *args, **kwargs):
        opens.append(path)
        raise PermissionError("denied")

    with patch("builtins.open", side_effect=counting_open):
        with patch("fivenines_agent.journal_policy.log"):
            for _ in range(5):
                assert journal_policy.unit_allowed("nginx.service") is False
    assert len(opens) == 1


# --- caching ---


def test_unchanged_file_is_not_reread(config_dir):
    write_allowlist(config_dir, "nginx.service\n")
    real_open = open
    calls = []

    def counting_open(path, *args, **kwargs):
        if str(path).endswith(journal_policy.ALLOWLIST_FILENAME):
            calls.append(path)
        return real_open(path, *args, **kwargs)

    with patch("builtins.open", side_effect=counting_open):
        for _ in range(5):
            journal_policy.unit_allowed("nginx.service")
    assert len(calls) == 1


def test_an_edited_file_is_picked_up(config_dir):
    path = write_allowlist(config_dir, "nginx.service\n")
    assert journal_policy.unit_allowed("mysql.service") is False

    path.write_text("nginx.service\nmysql.service\n")
    # No reset_cache(): the stat identity changed, which is what production
    # relies on between SIGHUPs.
    assert journal_policy.unit_allowed("mysql.service") is True


# --- filter_units reporting ---


def test_denied_units_are_reported_once_per_distinct_set(config_dir):
    write_allowlist(config_dir, "nginx.service\n")
    with patch("fivenines_agent.journal_policy.log") as mock_log:
        journal_policy.filter_units(["nginx.service", "mysql.service"])
        journal_policy.filter_units(["nginx.service", "mysql.service"])
        errors = [c for c in mock_log.call_args_list if c.args[1] == "error"]
        assert len(errors) == 1
        assert "mysql.service" in errors[0].args[0]

        # A different denial set is worth another line.
        journal_policy.filter_units(["redis.service"])
        errors = [c for c in mock_log.call_args_list if c.args[1] == "error"]
        assert len(errors) == 2


def test_a_denial_that_stops_and_returns_is_reported_again(config_dir):
    """The dedup latch must re-arm, or a re-added unit is refused silently."""
    write_allowlist(config_dir, "nginx.service\n")
    with patch("fivenines_agent.journal_policy.log") as mock_log:
        journal_policy.filter_units(["nginx.service", "mysql.service"])
        journal_policy.filter_units(["nginx.service"])  # denial stops
        journal_policy.filter_units(["nginx.service", "mysql.service"])  # returns
        errors = [c for c in mock_log.call_args_list if c.args[1] == "error"]
    assert len(errors) == 2


def test_an_edited_file_rearms_the_denial_report(config_dir):
    path = write_allowlist(config_dir, "nginx.service\n")
    with patch("fivenines_agent.journal_policy.log") as mock_log:
        journal_policy.filter_units(["nginx.service", "mysql.service"])
        assert len([c for c in mock_log.call_args_list if c.args[1] == "error"]) == 1
        path.write_text("nginx.service\nredis.service\n")  # new stat identity
        journal_policy.filter_units(["nginx.service", "mysql.service"])
        assert len([c for c in mock_log.call_args_list if c.args[1] == "error"]) == 2


def test_units_past_the_cap_are_reported_as_refused(config_dir):
    """The overflow is refused, so it must not vanish silently."""
    write_allowlist(config_dir, "*\n")
    units = [f"u{i}.service" for i in range(journal_policy.MAX_FILTER_UNITS + 3)]
    with patch("fivenines_agent.journal_policy.log") as mock_log:
        allowed, _refused = journal_policy.filter_units(units)
    assert len(allowed) == journal_policy.MAX_FILTER_UNITS
    errors = [c for c in mock_log.call_args_list if c.args[1] == "error"]
    assert len(errors) == 1
    assert "refusing 3 unit(s)" in errors[0].args[0]


def test_long_denial_lists_are_summarised(config_dir):
    write_allowlist(config_dir, "nginx.service\n")
    with patch("fivenines_agent.journal_policy.log") as mock_log:
        journal_policy.filter_units([f"u{i}.service" for i in range(9)])
    message = [c for c in mock_log.call_args_list if c.args[1] == "error"][0].args[0]
    assert "+4 more" in message
    # Names are sorted for display even though the dedup key is a set.
    assert "u0.service" in message


# --- every journal read honours it ---


def test_log_signals_report_refused_units(config_dir):
    """A refused unit must not render as a unit with zero errors."""
    write_allowlist(config_dir, "nginx.service\n")
    out = logs.collect_log_signals(
        units=["nginx.service", "mysql.service"],
        signal_interval_s=60,
        _entries_fn=lambda *a, **k: [],
    )
    assert out["refused_units"] == ["mysql.service"]


def test_log_signals_carry_no_refusal_key_when_nothing_is_refused(config_dir):
    write_allowlist(config_dir, "nginx.service\n")
    out = logs.collect_log_signals(
        units=["nginx.service"],
        signal_interval_s=60,
        _entries_fn=lambda *a, **k: [],
    )
    assert "refused_units" not in out


def test_log_signals_only_scan_allowed_units(config_dir):
    write_allowlist(config_dir, "nginx.service\n")
    seen = []

    def fake_entries(unit, since, lines, timeout=None):
        seen.append(unit)
        return []

    out = logs.collect_log_signals(
        units=["nginx.service", "mysql.service"],
        signal_interval_s=60,
        _entries_fn=fake_entries,
    )
    assert seen == ["nginx.service"]
    assert list(out["units"]) == ["nginx.service"]


def test_capture_entries_refuses_a_denied_unit_without_spawning_journalctl(config_dir):
    """The choke point: no future caller can read a journal the host forbids."""
    write_allowlist(config_dir, "nginx.service\n")
    with patch("fivenines_agent.logs.subprocess.run") as mock_run:
        assert logs._capture_entries("mysql.service", 0, 10) is None
    mock_run.assert_not_called()


def test_capture_is_refused_for_a_locally_denied_unit(config_dir, tmp_path):
    write_allowlist(config_dir, "nginx.service\n")
    coordinator = log_capture.CaptureCoordinator(str(tmp_path / "last_capture_id"))
    queue = MagicMock()
    queue.full.return_value = False
    config = {
        "logs": {"units": ["nginx.service", "mysql.service"]},
        "capture_logs": {"capture_id": "c1", "unit": "mysql.service"},
    }
    assert log_capture.evaluate_and_enqueue(coordinator, queue, config) is None
    queue.put.assert_not_called()


def test_capture_still_fires_for_an_allowed_unit(config_dir, tmp_path):
    write_allowlist(config_dir, "nginx.service\n")
    coordinator = log_capture.CaptureCoordinator(str(tmp_path / "last_capture_id"))
    queue = MagicMock()
    queue.full.return_value = False
    config = {
        "logs": {"units": ["nginx.service", "mysql.service"]},
        "capture_logs": {"capture_id": "c1", "unit": "nginx.service"},
    }
    job = log_capture.evaluate_and_enqueue(coordinator, queue, config)
    assert job["unit"] == "nginx.service"
    queue.put.assert_called_once()


def test_systemd_journal_tail_honours_the_allowlist(config_dir):
    """The failure drilldown ships journal content too, so it is bounded too."""
    write_allowlist(config_dir, "nginx.service\n")
    collector = systemd.SystemdCollector.__new__(systemd.SystemdCollector)
    with patch("fivenines_agent.systemd._run_journalctl") as mock_journalctl:
        assert collector._journal_tail("mysql.service") == []
    mock_journalctl.assert_not_called()


def test_the_local_allowlist_narrows_and_never_widens(config_dir, tmp_path):
    """The file is a veto, not a second source of units.

    Listing a unit locally cannot make the agent read a journal the SERVER
    never asked for -- on either journal path. This is the intersection the
    module exists to guarantee, so it is asserted from both ends rather than
    left to the fact that filter_units happens to iterate the server list.
    """
    write_allowlist(config_dir, "nginx.service\nmysql.service\n")
    seen = []

    def fake_entries(unit, since, lines, timeout=None):
        seen.append(unit)
        return []

    out = logs.collect_log_signals(
        units=["nginx.service"],
        signal_interval_s=60,
        _entries_fn=fake_entries,
    )
    assert seen == ["nginx.service"]
    assert list(out["units"]) == ["nginx.service"]

    # Same on the capture path: locally allowed, never requested -> refused.
    coordinator = log_capture.CaptureCoordinator(str(tmp_path / "last_capture_id"))
    queue = MagicMock()
    queue.full.return_value = False
    config = {
        "logs": {"units": ["nginx.service"]},
        "capture_logs": {"capture_id": "c1", "unit": "mysql.service"},
    }
    assert log_capture.evaluate_and_enqueue(coordinator, queue, config) is None
    queue.put.assert_not_called()
