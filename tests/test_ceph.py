import json
import os
import subprocess
from unittest.mock import patch

import pytest

from fivenines_agent import cache as cache_mod
from fivenines_agent import ceph
from fivenines_agent import permissions as perm_mod


class _FakeClock:
    def __init__(self):
        self.t = 1000.0

    def monotonic(self):
        return self.t


class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def clock(monkeypatch):
    c = _FakeClock()
    monkeypatch.setattr(cache_mod, "time", c)
    ceph._cache._entries.clear()
    yield c
    ceph._cache._entries.clear()


# --- ceph_metrics (entry point) -------------------------------------------


def test_metrics_no_clusters_returns_none(clock):
    """BY DESIGN (cross-repo contract): the server owns the default target.

    Empty means the server sent nothing to poll -- the agent must NOT invent a
    fallback cluster here. The standard enable path never sends an empty list:
    fivenines-server's ceph_targets_for_host returns [{"name": "ceph"}] when a
    host has no CephTarget override rows. If this pin breaks in either repo,
    the ownership of the default target has silently moved -- coordinate with
    fivenines-server (spec/requests/api_collect_ceph_spec.rb) before changing.
    """
    assert ceph.ceph_metrics(clusters=None) is None
    assert ceph.ceph_metrics(clusters=[]) is None


def test_metrics_ceph_absent_returns_none(clock):
    with patch.object(ceph.shutil, "which", lambda _: None):
        assert ceph.ceph_metrics(clusters=[{"name": "ceph"}]) is None


def test_metrics_polls_each_cluster(clock):
    with patch.object(ceph.shutil, "which", lambda _: "/usr/bin/ceph"), patch.object(
        ceph, "_poll_cluster", lambda c: {"configured_name": c["name"]}
    ):
        out = ceph.ceph_metrics(clusters=[{"name": "a"}, {"name": "b"}])
    assert out == {"clusters": [{"configured_name": "a"}, {"configured_name": "b"}]}


# --- _poll_cluster --------------------------------------------------------


def _fake_cmd_runner(mapping):
    """Return a _run_ceph_cached stub keyed by the command list."""

    def runner(base, cmd, name):
        return mapping.get(tuple(cmd), (None, {"type": "ceph_error", "message": "x"}))

    return runner


def test_poll_status_error_is_unreachable(clock):
    runner = _fake_cmd_runner(
        {("status",): (None, {"type": "unreachable", "message": "no mon"})}
    )
    with patch.object(ceph, "_run_ceph_cached", runner):
        result = ceph._poll_cluster({"name": "ceph"})
    assert result["collection"]["reachable"] is False
    assert result["collection"]["status_ok"] is False
    assert result["collection"]["error"]["type"] == "unreachable"
    assert result["fsid"] is None


def test_poll_full_success(clock):
    status = {
        "fsid": "abc",
        "health": {"status": "HEALTH_OK", "checks": {}},
        "quorum": [0, 1, 2],
        "monmap": {"mons": [1, 2, 3]},
        "osdmap": {"num_up_osds": 3, "num_in_osds": 3, "num_osds": 3},
        "pgmap": {
            "num_pgs": 10,
            "pgs_by_state": [{"state_name": "active+clean", "count": 10}],
            "read_bytes_sec": 2048,
            "write_op_per_sec": 7,
            "misplaced_objects": 3,
        },
    }
    df = {
        "stats": {"total_bytes": 100, "total_used_bytes": 40, "total_avail_bytes": 60},
        "pools": [
            {"name": "rbd", "id": 2, "stats": {"stored": 40, "objects": 5,
                                               "percent_used": 0.4, "max_avail": 60}}
        ],
    }
    tree = {"nodes": [{"type": "host", "name": "h1", "children": [0, 1]}]}
    perf = {
        "osdstats": {
            "osd_perf_infos": [
                {"id": 0, "perf_stats": {"commit_latency_ms": 2, "apply_latency_ms": 2}}
            ]
        }
    }
    osd_df = {
        "nodes": [
            {"id": 0, "name": "osd.0", "kb": 100, "kb_used": 40, "kb_avail": 60,
             "utilization": 40.0, "status": "up"}
        ]
    }
    runner = _fake_cmd_runner(
        {
            ("status",): (status, None),
            ("df",): (df, None),
            ("osd", "tree"): (tree, None),
            ("osd", "perf"): (perf, None),
            ("osd", "df"): (osd_df, None),
        }
    )
    with patch.object(ceph, "_run_ceph_cached", runner):
        r = ceph._poll_cluster({"name": "ceph"})

    assert r["collection"] == {
        "reachable": True,
        "status_ok": True,
        "df_ok": True,
        "tree_ok": True,
        "perf_ok": True,
        "osd_df_ok": True,
        "error": None,
    }
    assert r["fsid"] == "abc"
    assert r["health"] == {"status": "HEALTH_OK", "checks": []}
    assert r["mon"] == {"in_quorum": 3, "total": 3}
    assert r["osd"] == {"up": 3, "in": 3, "total": 3}
    assert r["pg"] == {"total": 10, "degraded": 0, "inactive": 0, "undersized": 0}
    # io/recovery: present keys forwarded, absent keys normalized to 0.
    assert r["io"] == {
        "read_bytes_sec": 2048,
        "write_bytes_sec": 0,
        "read_op_per_sec": 0,
        "write_op_per_sec": 7,
    }
    assert r["recovery"]["misplaced_objects"] == 3
    assert r["recovery"]["degraded_total"] == 0
    assert r["osd_fullness"] == {"nearfull": None, "full": None}
    assert r["capacity"] == {"total_bytes": 100, "used_bytes": 40, "avail_bytes": 60}
    assert r["pools"] == [
        {"name": "rbd", "id": 2, "stored_bytes": 40, "objects": 5,
         "percent_used": 0.4, "max_avail_bytes": 60}
    ]
    assert r["pools_truncated"] is False
    assert r["osd_perf"] == [{"id": 0, "commit_latency_ms": 2, "apply_latency_ms": 2}]
    assert r["osd_perf_truncated"] is False
    assert r["osd_df"] == [
        {"id": 0, "name": "osd.0", "utilization": 40.0, "total_bytes": 102400,
         "used_bytes": 40960, "avail_bytes": 61440, "status": "up"}
    ]
    assert r["osd_df_truncated"] is False
    assert r["hosts"] == [{"host": "h1", "osd_count": 2}]


def test_poll_partial_df_and_tree_fail(clock):
    status = {"fsid": "abc", "health": "HEALTH_WARN"}
    runner = _fake_cmd_runner(
        {
            ("status",): (status, None),
            ("df",): (None, {"type": "ceph_error", "message": "df boom"}),
            ("osd", "tree"): (None, {"type": "ceph_error", "message": "tree boom"}),
        }
    )
    with patch.object(ceph, "_run_ceph_cached", runner):
        r = ceph._poll_cluster({"name": "ceph"})

    assert r["collection"]["reachable"] is True
    assert r["collection"]["status_ok"] is True
    assert r["collection"]["df_ok"] is False
    assert r["collection"]["tree_ok"] is False
    assert r["capacity"] is None
    assert r["hosts"] is None
    assert r["health"] == {"status": "HEALTH_WARN", "checks": []}


# --- _base_args -----------------------------------------------------------


def test_base_args_defaults():
    args = ceph._base_args({"name": "ceph"})
    assert "--connect-timeout" in args and "5" in args
    assert "--cluster" not in args  # default cluster name omitted
    assert "--name" in args and "client.fivenines" in args
    assert "--keyring" not in args  # default search path


def test_base_args_custom_cluster_conf_keyring_id():
    args = ceph._base_args(
        {"name": "prod", "conf": "/etc/ceph/prod.conf", "keyring": "/k", "id": "agent"}
    )
    assert args[args.index("--cluster") + 1] == "prod"
    assert args[args.index("-c") + 1] == "/etc/ceph/prod.conf"
    assert args[args.index("--name") + 1] == "client.agent"
    assert args[args.index("--keyring") + 1] == "/k"


def test_base_args_use_sudo_logs_but_keyring_only():
    with patch.object(ceph, "log") as mock_log:
        args = ceph._base_args({"name": "ceph", "use_sudo": True})
    assert "sudo" not in " ".join(args)  # not wired in v1
    assert mock_log.called


# --- _run_ceph ------------------------------------------------------------


def test_run_ceph_success_parses_json():
    proc = _FakeProc(0, json.dumps({"fsid": "x"}))
    with patch.object(ceph.subprocess, "run", lambda *a, **k: proc):
        out, err = ceph._run_ceph([], ["status"], "ceph")
    assert err is None
    assert out == {"fsid": "x"}


def test_run_ceph_nonzero_classifies_auth():
    proc = _FakeProc(1, "", "auth: access denied")
    with patch.object(ceph.subprocess, "run", lambda *a, **k: proc):
        out, err = ceph._run_ceph([], ["status"], "ceph")
    assert out is None
    assert err["type"] == "auth_error"


def test_run_ceph_timeout():
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="ceph", timeout=15)

    with patch.object(ceph.subprocess, "run", boom):
        out, err = ceph._run_ceph([], ["status"], "ceph")
    assert out is None
    assert err["type"] == "timeout"


def test_run_ceph_unknown_exception():
    def boom(*a, **k):
        raise OSError("nope")

    with patch.object(ceph.subprocess, "run", boom):
        out, err = ceph._run_ceph([], ["status"], "ceph")
    assert err["type"] == "unknown"


def test_run_ceph_parse_error():
    proc = _FakeProc(0, "not json")
    with patch.object(ceph.subprocess, "run", lambda *a, **k: proc):
        out, err = ceph._run_ceph([], ["status"], "ceph")
    assert out is None
    assert err["type"] == "parse_error"


def test_classify_error_variants():
    assert ceph._classify_error("permission denied") == "auth_error"
    assert ceph._classify_error("unable to connect to cluster") == "unreachable"
    assert ceph._classify_error("some other failure") == "ceph_error"


# --- caching --------------------------------------------------------------


def test_run_ceph_cached_hits_within_ttl(clock):
    calls = []

    def fake_run(base, cmd, name):
        calls.append(tuple(cmd))
        return ({"ok": True}, None)

    with patch.object(ceph, "_run_ceph", fake_run):
        ceph._run_ceph_cached([], ["status"], "ceph")
        clock.t += 10  # inside CACHE_TTL (30s)
        ceph._run_ceph_cached([], ["status"], "ceph")
        clock.t += 30  # past TTL
        ceph._run_ceph_cached([], ["status"], "ceph")

    assert calls == [("status",), ("status",)]  # 1 within TTL, 1 after


# --- parsers --------------------------------------------------------------


def test_parse_health_string_form():
    assert ceph._parse_health({"health": "HEALTH_ERR"}) == {
        "status": "HEALTH_ERR",
        "checks": [],
    }


def test_parse_health_dict_with_checks():
    out = ceph._parse_health(
        {
            "health": {
                "status": "HEALTH_WARN",
                "checks": {"OSD_DOWN": {}, "PG_DEGRADED": {}},
            }
        }
    )
    assert out["status"] == "HEALTH_WARN"
    assert sorted(out["checks"]) == ["OSD_DOWN", "PG_DEGRADED"]


def test_parse_health_overall_status_fallback():
    assert ceph._parse_health({"overall_status": "HEALTH_OK"}) == {
        "status": "HEALTH_OK",
        "checks": [],
    }


def test_parse_health_unknown():
    assert ceph._parse_health({}) == {"status": "UNKNOWN", "checks": []}


def test_parse_mon_num_mons_fallback_and_no_quorum():
    out = ceph._parse_mon({"monmap": {"num_mons": 5}})
    assert out == {"in_quorum": None, "total": 5}


def test_parse_osd_nested_form():
    status = {"osdmap": {"osdmap": {"num_up_osds": 2, "num_in_osds": 2, "num_osds": 4}}}
    assert ceph._parse_osd(status) == {"up": 2, "in": 2, "total": 4}


def test_parse_pg_overlap_and_inactive():
    status = {
        "pgmap": {
            "num_pgs": 100,
            "pgs_by_state": [
                {"state_name": "active+clean", "count": 90},
                {"state_name": "active+undersized+degraded", "count": 7},
                {"state_name": "stale+peering", "count": 3},
            ],
        }
    }
    pg = ceph._parse_pg(status)
    assert pg["total"] == 100
    assert pg["degraded"] == 7
    assert pg["undersized"] == 7
    assert pg["inactive"] == 3  # only the non-active state


def test_parse_pg_empty():
    assert ceph._parse_pg({}) == {
        "total": None,
        "degraded": 0,
        "inactive": 0,
        "undersized": 0,
    }


def test_parse_capacity_raw_fallback():
    df = {
        "stats": {"total_bytes": 10, "total_used_raw_bytes": 4, "total_avail_bytes": 6}
    }
    assert ceph._parse_capacity(df) == {
        "total_bytes": 10,
        "used_bytes": 4,
        "avail_bytes": 6,
    }


def test_parse_host_osd_counts_non_list_nodes():
    assert ceph._parse_host_osd_counts({}) == []


def test_parse_host_osd_counts_children_non_list():
    tree = {"nodes": [{"type": "host", "name": "h1", "children": None}]}
    assert ceph._parse_host_osd_counts(tree) == [{"host": "h1", "osd_count": 0}]


# --- capability probe -----------------------------------------------------


def test_can_run_ceph_present(monkeypatch):
    monkeypatch.setattr(perm_mod.shutil, "which", lambda _: "/usr/bin/ceph")
    probe = perm_mod.PermissionProbe.__new__(perm_mod.PermissionProbe)
    probe._current_reason = None
    assert probe._can_run_ceph() is True


def test_can_run_ceph_absent_sets_reason(monkeypatch):
    monkeypatch.setattr(perm_mod.shutil, "which", lambda _: None)
    probe = perm_mod.PermissionProbe.__new__(perm_mod.PermissionProbe)
    probe._current_reason = None
    assert probe._can_run_ceph() is False
    assert "not found" in probe._current_reason


# --- per-cluster isolation ------------------------------------------------


def test_metrics_skips_non_dict_cluster(clock):
    with patch.object(ceph.shutil, "which", lambda _: "/usr/bin/ceph"), patch.object(
        ceph, "_poll_cluster", lambda c: {"configured_name": c["name"]}
    ):
        out = ceph.ceph_metrics(clusters=["bad", {"name": "ok"}])
    assert out == {"clusters": [{"configured_name": "ok"}]}


def test_metrics_isolates_cluster_exception(clock):
    def boom(c):
        if c["name"] == "bad":
            raise ValueError("kaboom")
        return {"configured_name": c["name"]}

    with patch.object(ceph.shutil, "which", lambda _: "/usr/bin/ceph"), patch.object(
        ceph, "_poll_cluster", boom
    ):
        out = ceph.ceph_metrics(clusters=[{"name": "bad"}, {"name": "ok"}])

    clusters = out["clusters"]
    assert clusters[0]["configured_name"] == "bad"
    assert clusters[0]["collection"]["error"]["type"] == "unknown"
    assert clusters[1] == {"configured_name": "ok"}


def test_run_ceph_cached_does_not_cache_errors(clock):
    calls = []

    def fake_run(base, cmd, name):
        calls.append(tuple(cmd))
        return (None, {"type": "unreachable", "message": "down"})

    with patch.object(ceph, "_run_ceph", fake_run):
        ceph._run_ceph_cached([], ["status"], "ceph")
        clock.t += 1  # well inside CACHE_TTL
        ceph._run_ceph_cached([], ["status"], "ceph")

    assert calls == [("status",), ("status",)]  # error not cached -> retried


# --- defensive parsing ----------------------------------------------------


def test_parse_pg_ignores_bad_entries():
    status = {
        "pgmap": {
            "num_pgs": 5,
            "pgs_by_state": [
                "notadict",
                {"state_name": 123, "count": 2},  # non-str name -> "" -> inactive
                {"state_name": "active+clean", "count": "x"},  # non-int count -> 0
            ],
        }
    }
    pg = ceph._parse_pg(status)
    assert pg == {"total": 5, "degraded": 0, "inactive": 2, "undersized": 0}


def test_parse_mon_non_dict_monmap():
    assert ceph._parse_mon({"monmap": ["x"], "quorum": [0]}) == {
        "in_quorum": 1,
        "total": None,
    }


def test_parse_osd_non_dict_osdmap():
    assert ceph._parse_osd({"osdmap": "weird"}) == {
        "up": None,
        "in": None,
        "total": None,
    }


def test_parse_pg_non_dict_pgmap():
    assert ceph._parse_pg({"pgmap": "weird"}) == {
        "total": None,
        "degraded": 0,
        "inactive": 0,
        "undersized": 0,
    }


def test_parse_pg_bool_count_is_zero():
    status = {
        "pgmap": {
            "num_pgs": 1,
            "pgs_by_state": [{"state_name": "degraded", "count": True}],
        }
    }
    # bool is an int subclass; it must be rejected, not added as 1.
    assert ceph._parse_pg(status)["degraded"] == 0


def test_parse_capacity_non_dict_stats():
    assert ceph._parse_capacity({"stats": "weird"}) == {
        "total_bytes": None,
        "used_bytes": None,
        "avail_bytes": None,
    }


# --- top-level JSON shape + cache key (code-review fixes) ------------------


def test_run_ceph_non_dict_json_is_parse_error():
    for body in ("null", "[]", "42"):
        proc = _FakeProc(0, body)
        with patch.object(ceph.subprocess, "run", lambda *a, **k: proc):
            out, err = ceph._run_ceph([], ["status"], "ceph")
        assert out is None
        assert err["type"] == "parse_error"


def test_run_ceph_cached_keys_on_base_not_just_name(clock):
    # Two clusters sharing name+cmd but different connection args (base) must
    # NOT collide in the cache -- each computes its own result.
    calls = []

    def fake_run(base, cmd, name):
        calls.append(tuple(base))
        return ({"conf": base[-1]}, None)

    with patch.object(ceph, "_run_ceph", fake_run):
        a = ceph._run_ceph_cached(["-c", "a.conf"], ["status"], "ceph")
        b = ceph._run_ceph_cached(["-c", "b.conf"], ["status"], "ceph")

    assert calls == [("-c", "a.conf"), ("-c", "b.conf")]  # both ran, no collision
    assert a == ({"conf": "a.conf"}, None)
    assert b == ({"conf": "b.conf"}, None)


def test_classify_error_auth_timeout_is_unreachable():
    # mon hunting: "authenticate timed out" is an outage, not a keyring problem.
    assert ceph._classify_error("monclient(hunting): authenticate timed out") == (
        "unreachable"
    )
    assert ceph._classify_error("RADOS permission denied") == "auth_error"


# --- round 2 review fixes -------------------------------------------------


def test_parse_host_osd_counts_skips_non_dict_node():
    tree = {"nodes": ["osd.0", None, {"type": "host", "name": "h1", "children": [0]}]}
    assert ceph._parse_host_osd_counts(tree) == [{"host": "h1", "osd_count": 1}]


def test_base_args_coerces_mistyped_values_to_str():
    args = ceph._base_args({"name": 123, "conf": ["/a"], "keyring": {"k": 1}, "id": 7})
    # All coerced to str: no raise, and tuple(args) stays hashable for the key.
    assert all(isinstance(a, str) for a in args)
    assert hash(tuple(args))  # raises TypeError if any element is unhashable
    assert args[args.index("--cluster") + 1] == "123"
    assert args[args.index("--name") + 1] == "client.7"


def test_base_args_empty_id_falls_back():
    args = ceph._base_args({"name": "ceph", "id": ""})
    assert args[args.index("--name") + 1] == "client.fivenines"


def test_base_args_null_name_omits_cluster_flag():
    assert "--cluster" not in ceph._base_args({"name": None})


def test_poll_null_name_defaults_to_ceph(clock):
    runner = _fake_cmd_runner({("status",): ({"fsid": "x"}, None)})
    with patch.object(ceph, "_run_ceph_cached", runner):
        r = ceph._poll_cluster({"name": None})
    assert r["configured_name"] == "ceph"


def test_metrics_tolerates_extra_config_keys(clock):
    with patch.object(ceph.shutil, "which", lambda _: "/usr/bin/ceph"), patch.object(
        ceph, "_poll_cluster", lambda c: {"configured_name": c["name"]}
    ):
        # Forward-compat: an unknown top-level config key must not crash/blank
        # the collector (caught by **_).
        out = ceph.ceph_metrics(clusters=[{"name": "a"}], poll_mode="fast")
    assert out == {"clusters": [{"configured_name": "a"}]}


# --- v2: io / recovery / osd_fullness (from status) ------------------------


def test_parse_io_absent_keys_zero_filled():
    # Idle cluster: mgr omits the io keys -> normalized to 0, object still emitted.
    assert ceph._parse_io({"pgmap": {}}) == {
        "read_bytes_sec": 0,
        "write_bytes_sec": 0,
        "read_op_per_sec": 0,
        "write_op_per_sec": 0,
    }


def test_parse_io_non_dict_pgmap():
    assert ceph._parse_io({"pgmap": "weird"}) == {
        "read_bytes_sec": 0,
        "write_bytes_sec": 0,
        "read_op_per_sec": 0,
        "write_op_per_sec": 0,
    }


def test_parse_io_forwards_present_values():
    out = ceph._parse_io(
        {
            "pgmap": {
                "read_bytes_sec": 10,
                "write_bytes_sec": 20,
                "read_op_per_sec": 3,
                "write_op_per_sec": 4,
            }
        }
    )
    assert out == {
        "read_bytes_sec": 10,
        "write_bytes_sec": 20,
        "read_op_per_sec": 3,
        "write_op_per_sec": 4,
    }


def test_num_or_zero_variants():
    assert ceph._num_or_zero(5) == 5
    assert ceph._num_or_zero(1.5) == 1.5
    assert ceph._num_or_zero(None) == 0
    assert ceph._num_or_zero("x") == 0
    assert ceph._num_or_zero(True) == 0  # bool is an int subclass -> rejected


def test_parse_recovery_absent_and_present():
    out = ceph._parse_recovery({"pgmap": {"misplaced_objects": 7, "degraded_total": 9}})
    assert out == {
        "recovering_objects_per_sec": 0,
        "recovering_bytes_per_sec": 0,
        "misplaced_objects": 7,
        "misplaced_total": 0,
        "degraded_objects": 0,
        "degraded_total": 9,
    }


def test_parse_recovery_non_dict_pgmap():
    assert ceph._parse_recovery({"pgmap": None})["misplaced_objects"] == 0


def test_parse_osd_fullness_count_path():
    status = {
        "health": {
            "checks": {
                "OSD_NEARFULL": {
                    "summary": {"message": "3 nearfull osd(s)", "count": 3}
                },
                "OSD_FULL": {"summary": {"message": "1 full osd(s)", "count": 1}},
            }
        }
    }
    assert ceph._parse_osd_fullness(status) == {"nearfull": 3, "full": 1}


def test_parse_osd_fullness_message_fallback():
    # No count key -> parse the leading integer of the human message.
    status = {
        "health": {"checks": {"OSD_NEARFULL": {"summary": {"message": "5 nearfull"}}}}
    }
    assert ceph._parse_osd_fullness(status) == {"nearfull": 5, "full": None}


def test_parse_osd_fullness_absent_checks_are_null():
    # Healthy cluster: no nearfull/full checks -> null (unknown), never a faked 0.
    assert ceph._parse_osd_fullness({"health": {"checks": {}}}) == {
        "nearfull": None,
        "full": None,
    }


def test_parse_osd_fullness_health_non_dict():
    assert ceph._parse_osd_fullness({"health": "HEALTH_OK"}) == {
        "nearfull": None,
        "full": None,
    }


def test_parse_osd_fullness_checks_non_dict():
    assert ceph._parse_osd_fullness({"health": {"checks": "weird"}}) == {
        "nearfull": None,
        "full": None,
    }


def test_extract_fullness_count_bool_count_falls_back_to_message():
    # bool count is rejected (int subclass); the message is parsed instead.
    check = {"summary": {"message": "4 nearfull osd(s)", "count": True}}
    assert ceph._extract_fullness_count(check) == 4


def test_extract_fullness_count_summary_non_dict():
    assert ceph._extract_fullness_count({"summary": "x"}) is None


def test_extract_fullness_count_unparseable_message_is_none():
    # Present-but-unparseable check -> None, NOT a fabricated 0 (would silence
    # a real nearfull/full alert).
    assert ceph._extract_fullness_count({"summary": {"message": "osds nearfull"}}) is None


def test_extract_fullness_count_non_str_message_is_none():
    assert ceph._extract_fullness_count({"summary": {"message": 123}}) is None


def test_leading_int_no_digits():
    assert ceph._leading_int("no number here") is None


# --- v2: pools (from df) ---------------------------------------------------


def test_parse_pools_non_list():
    assert ceph._parse_pools({"pools": "weird"}) == ([], False)
    assert ceph._parse_pools({}) == ([], False)


def test_parse_pools_maps_and_skips_non_dict():
    df = {
        "pools": [
            "notadict",
            {
                "name": "rbd",
                "id": 2,
                "stats": {
                    "stored": 40,
                    "objects": 5,
                    "percent_used": 0.4,
                    "max_avail": 60,
                },
            },
        ]
    }
    pools, truncated = ceph._parse_pools(df)
    assert truncated is False
    assert pools == [
        {
            "name": "rbd",
            "id": 2,
            "stored_bytes": 40,
            "objects": 5,
            "percent_used": 0.4,
            "max_avail_bytes": 60,
        }
    ]


def test_parse_pools_stats_non_dict():
    df = {"pools": [{"name": "p", "id": 1, "stats": "weird"}]}
    pools, _ = ceph._parse_pools(df)
    assert pools == [
        {
            "name": "p",
            "id": 1,
            "stored_bytes": None,
            "objects": None,
            "percent_used": None,
            "max_avail_bytes": None,
        }
    ]


def test_parse_pools_truncation(monkeypatch):
    monkeypatch.setattr(ceph, "POOLS_CAP", 2)
    df = {"pools": [{"name": "a"}, {"name": "b"}, {"name": "c"}]}
    pools, truncated = ceph._parse_pools(df)
    assert truncated is True
    assert len(pools) == 2


# --- v2: osd_perf / osd_df (new commands) ----------------------------------


def test_kb_to_bytes_variants():
    assert ceph._kb_to_bytes(1) == 1024
    assert ceph._kb_to_bytes(2.5) == 2560
    assert ceph._kb_to_bytes(None) is None
    assert ceph._kb_to_bytes("x") is None
    assert ceph._kb_to_bytes(True) is None  # bool rejected


def test_osd_perf_infos_nested_shape():
    assert ceph._osd_perf_infos({"osdstats": {"osd_perf_infos": [{"id": 0}]}}) == [
        {"id": 0}
    ]


def test_osd_perf_infos_legacy_top_level_shape():
    assert ceph._osd_perf_infos({"osd_perf_infos": [{"id": 1}]}) == [{"id": 1}]


def test_osd_perf_infos_nested_non_list_falls_through():
    # osdstats present but osd_perf_infos not a list -> top-level absent -> [].
    assert ceph._osd_perf_infos({"osdstats": {"osd_perf_infos": "x"}}) == []


def test_osd_perf_infos_neither_shape():
    assert ceph._osd_perf_infos({}) == []


def test_parse_osd_perf_maps_and_skips_non_dict():
    perf = {
        "osdstats": {
            "osd_perf_infos": [
                "notadict",
                {
                    "id": 0,
                    "perf_stats": {"commit_latency_ms": 3, "apply_latency_ms": 4},
                },
            ]
        }
    }
    result, truncated = ceph._parse_osd_perf(perf)
    assert truncated is False
    assert result == [{"id": 0, "commit_latency_ms": 3, "apply_latency_ms": 4}]


def test_parse_osd_perf_perf_stats_non_dict():
    perf = {"osd_perf_infos": [{"id": 2, "perf_stats": "weird"}]}
    result, _ = ceph._parse_osd_perf(perf)
    assert result == [{"id": 2, "commit_latency_ms": None, "apply_latency_ms": None}]


def test_parse_osd_perf_truncation(monkeypatch):
    monkeypatch.setattr(ceph, "OSD_CAP", 1)
    perf = {"osdstats": {"osd_perf_infos": [{"id": 0}, {"id": 1}]}}
    result, truncated = ceph._parse_osd_perf(perf)
    assert truncated is True
    assert len(result) == 1


def test_parse_osd_df_non_list_nodes():
    assert ceph._parse_osd_df({"nodes": "weird"}) == ([], False)
    assert ceph._parse_osd_df({}) == ([], False)


def test_parse_osd_df_maps_kb_and_skips_non_dict():
    osd_df = {
        "nodes": [
            "notadict",
            {
                "id": 0,
                "name": "osd.0",
                "kb": 100,
                "kb_used": 40,
                "kb_avail": 60,
                "utilization": 40.0,
                "status": "up",
            },
        ]
    }
    result, truncated = ceph._parse_osd_df(osd_df)
    assert truncated is False
    assert result == [
        {
            "id": 0,
            "name": "osd.0",
            "utilization": 40.0,
            "total_bytes": 102400,
            "used_bytes": 40960,
            "avail_bytes": 61440,
            "status": "up",
        }
    ]


def test_parse_osd_df_absent_kb_fields_are_none():
    osd_df = {"nodes": [{"id": 1, "name": "osd.1", "utilization": 0.0, "status": "up"}]}
    result, _ = ceph._parse_osd_df(osd_df)
    assert result == [
        {
            "id": 1,
            "name": "osd.1",
            "utilization": 0.0,
            "total_bytes": None,
            "used_bytes": None,
            "avail_bytes": None,
            "status": "up",
        }
    ]


def test_parse_osd_df_truncation(monkeypatch):
    monkeypatch.setattr(ceph, "OSD_CAP", 1)
    osd_df = {"nodes": [{"id": 0}, {"id": 1}]}
    result, truncated = ceph._parse_osd_df(osd_df)
    assert truncated is True
    assert len(result) == 1


def test_poll_perf_and_osd_df_failure_isolated(clock):
    # A perf/osd_df command failure must NOT touch the core sections: the two
    # *_ok flags stay False and the values stay None, like df/tree isolation.
    status = {"fsid": "abc", "health": "HEALTH_OK"}
    runner = _fake_cmd_runner(
        {
            ("status",): (status, None),
            ("df",): ({"stats": {"total_bytes": 1}}, None),
            ("osd", "tree"): ({"nodes": []}, None),
        }  # osd perf + osd df unmapped -> _fake_cmd_runner returns a ceph_error
    )
    with patch.object(ceph, "_run_ceph_cached", runner), patch.object(ceph, "log"):
        r = ceph._poll_cluster({"name": "ceph"})
    assert r["collection"]["status_ok"] is True
    assert r["collection"]["df_ok"] is True
    assert r["collection"]["perf_ok"] is False
    assert r["collection"]["osd_df_ok"] is False
    assert r["osd_perf"] is None
    assert r["osd_df"] is None
    assert r["osd_perf_truncated"] is False
    assert r["osd_df_truncated"] is False


# --- cross-repo contract (fivenines-server) ---------------------------------


class _KeySpy(dict):
    """Dict that records every key consulted via .get()."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.accessed = set()

    def get(self, key, default=None):
        self.accessed.add(key)
        return super().get(key, default)


def test_config_key_names_match_server_contract(clock):
    """Documented server shape (ceph_targets_for_host): a cluster entry carries
    exactly name, id, keyring, conf, use_sudo -- blank keyring/conf are omitted
    server-side (.compact), so absence must mean "standard search path".

    Two-way pin: every documented key is consulted and takes effect (drift =
    the agent ignores server config), and NO other key is consulted (drift =
    the agent invents a key the server never sends). Fix any mismatch toward
    the server's names.
    """
    cluster = _KeySpy(
        name="prod",
        id="agent",
        keyring="/etc/ceph/prod.client.agent.keyring",
        conf="/etc/ceph/prod.conf",
        use_sudo=True,
    )
    seen = {}

    def runner(base, cmd, name):
        seen["base"] = base
        return (None, {"type": "unreachable", "message": "x"})

    with patch.object(ceph, "_run_ceph_cached", runner), patch.object(ceph, "log"):
        ceph._poll_cluster(cluster)

    base = seen["base"]
    assert base[base.index("--cluster") + 1] == "prod"
    assert base[base.index("-c") + 1] == "/etc/ceph/prod.conf"
    assert base[base.index("--name") + 1] == "client.agent"
    assert base[base.index("--keyring") + 1] == "/etc/ceph/prod.client.agent.keyring"
    assert cluster.accessed == {"name", "id", "keyring", "conf", "use_sudo"}


# Canned `ceph ... -f json` CLI outputs backing the shared fixture. Realistic
# (Reef-era) shapes trimmed to the fields the parsers read: 3 mons in quorum,
# 1 of 3 OSDs down, 2 nearfull, 12 PGs undersized+degraded, 2 CRUSH host
# buckets, active client I/O + a recovery in progress.
_CLI_STATUS = {
    "fsid": "3f6ad3d1-8f6e-4a5b-9e6c-2f4a1b8c9d0e",
    "health": {
        "status": "HEALTH_WARN",
        "checks": {
            "OSD_DOWN": {"severity": "HEALTH_WARN"},
            # count present -> used directly; OSD_FULL absent -> full is null.
            "OSD_NEARFULL": {
                "severity": "HEALTH_WARN",
                "summary": {"message": "2 nearfull osd(s)", "count": 2},
            },
        },
    },
    "quorum": [0, 1, 2],
    "monmap": {"mons": [{"name": "a"}, {"name": "b"}, {"name": "c"}]},
    "osdmap": {"num_osds": 3, "num_up_osds": 2, "num_in_osds": 3},
    "pgmap": {
        "num_pgs": 129,
        "pgs_by_state": [
            {"state_name": "active+clean", "count": 117},
            {"state_name": "active+undersized+degraded", "count": 12},
        ],
        "read_bytes_sec": 104857600,
        "write_bytes_sec": 52428800,
        "read_op_per_sec": 1500,
        "write_op_per_sec": 750,
        "recovering_objects_per_sec": 240,
        "recovering_bytes_per_sec": 1006632960,
        "misplaced_objects": 1024,
        "misplaced_total": 200000,
        "degraded_objects": 512,
        "degraded_total": 200000,
    },
}
_CLI_DF = {
    "stats": {
        "total_bytes": 32212254720,
        "total_used_bytes": 12884901888,
        "total_avail_bytes": 19327352832,
    },
    "pools": [
        {
            "name": "device_health_metrics",
            "id": 1,
            "stats": {
                "stored": 0,
                "objects": 0,
                "percent_used": 0.0,
                "max_avail": 6120000000,
            },
        },
        {
            "name": "rbd",
            "id": 2,
            "stats": {
                "stored": 6442450944,
                "objects": 1580,
                "percent_used": 0.1,
                "max_avail": 6120000000,
            },
        },
    ],
}
_CLI_TREE = {
    "nodes": [
        {"id": -1, "name": "default", "type": "root", "children": [-3, -2]},
        {"id": -2, "name": "node-1", "type": "host", "children": [0, 1]},
        {"id": -3, "name": "node-2", "type": "host", "children": [2]},
        {"id": 0, "name": "osd.0", "type": "osd"},
        {"id": 1, "name": "osd.1", "type": "osd"},
        {"id": 2, "name": "osd.2", "type": "osd"},
    ]
}
# Nautilus+ nests the perf list under osdstats; the parser also accepts the
# older top-level osd_perf_infos shape (see test_parse_osd_perf_legacy_shape).
_CLI_OSD_PERF = {
    "osdstats": {
        "osd_perf_infos": [
            {"id": 0, "perf_stats": {"commit_latency_ms": 3, "apply_latency_ms": 3}},
            {"id": 1, "perf_stats": {"commit_latency_ms": 5, "apply_latency_ms": 5}},
            {"id": 2, "perf_stats": {"commit_latency_ms": 1, "apply_latency_ms": 1}},
        ]
    }
}
# kb_* fields (KiB) are converted to bytes (x1024) by the agent. Each OSD is
# 10 GiB; osd.1 is 80% full, osd.2 is down.
_CLI_OSD_DF = {
    "nodes": [
        {"id": 0, "name": "osd.0", "kb": 10485760, "kb_used": 4194304,
         "kb_avail": 6291456, "utilization": 40.0, "status": "up"},
        {"id": 1, "name": "osd.1", "kb": 10485760, "kb_used": 8388608,
         "kb_avail": 2097152, "utilization": 80.0, "status": "up"},
        {"id": 2, "name": "osd.2", "kb": 10485760, "kb_used": 2097152,
         "kb_avail": 8388608, "utilization": 20.0, "status": "down"},
    ],
    "stray": [],
    "summary": {"total_kb": 31457280, "average_utilization": 46.67},
}

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "ceph_contract_payload.json"
)


def test_contract_fixture_round_trip(clock):
    """SHARED FIXTURE (cross-repo contract): fixtures/ceph_contract_payload.json.

    The same file is asserted on both sides:
    - here: ceph_metrics(**fixture["config"]) must equal fixture["payload"]
      with only subprocess.run mocked (canned CLI JSON above), so the whole
      config-in -> parse -> payload-out pipeline is pinned;
    - fivenines-server: spec/requests/api_collect_ceph_spec.rb posts
      fixture["payload"] under data["ceph"] and asserts Ingesters::Ceph
      ingests it (metrics are gated on the collection *_ok flags).

    Change the payload shape only in lockstep with the server spec and its
    fixture copy.
    """
    with open(_FIXTURE_PATH) as f:
        fixture = json.load(f)

    def fake_run(argv, **kwargs):
        # Route on the most specific token first: `osd tree`/`osd perf` both
        # carry "osd", and `osd df` shares "df" with plain `df`, so the unique
        # verbs (tree/perf) are matched before the generic "osd"/"df" fallbacks.
        if "edge" in argv:  # second cluster: unreachable
            return _FakeProc(1, "", "unable to connect to cluster")
        if "status" in argv:
            return _FakeProc(0, json.dumps(_CLI_STATUS))
        if "tree" in argv:
            return _FakeProc(0, json.dumps(_CLI_TREE))
        if "perf" in argv:
            return _FakeProc(0, json.dumps(_CLI_OSD_PERF))
        if "osd" in argv:  # osd df (osd + df, after tree/perf ruled out)
            return _FakeProc(0, json.dumps(_CLI_OSD_DF))
        assert "df" in argv, "unexpected ceph subcommand: {}".format(argv)
        return _FakeProc(0, json.dumps(_CLI_DF))

    with patch.object(ceph.shutil, "which", lambda _: "/usr/bin/ceph"), patch.object(
        ceph.subprocess, "run", fake_run
    ):
        out = ceph.ceph_metrics(**fixture["config"])

    assert out == fixture["payload"]
    # Completeness flags, explicitly: exactly the names the server's ingester
    # reads. A renamed or dropped flag must fail here, not silently zero the
    # server-side metrics.
    for cluster in out["clusters"]:
        assert set(cluster["collection"]) == {
            "reachable",
            "status_ok",
            "df_ok",
            "tree_ok",
            "perf_ok",
            "osd_df_ok",
            "error",
        }
