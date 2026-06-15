import json
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
        },
    }
    df = {
        "stats": {"total_bytes": 100, "total_used_bytes": 40, "total_avail_bytes": 60}
    }
    tree = {"nodes": [{"type": "host", "name": "h1", "children": [0, 1]}]}
    runner = _fake_cmd_runner(
        {
            ("status",): (status, None),
            ("df",): (df, None),
            ("osd", "tree"): (tree, None),
        }
    )
    with patch.object(ceph, "_run_ceph_cached", runner):
        r = ceph._poll_cluster({"name": "ceph"})

    assert r["collection"] == {
        "reachable": True,
        "status_ok": True,
        "df_ok": True,
        "tree_ok": True,
        "error": None,
    }
    assert r["fsid"] == "abc"
    assert r["health"] == {"status": "HEALTH_OK", "checks": []}
    assert r["mon"] == {"in_quorum": 3, "total": 3}
    assert r["osd"] == {"up": 3, "in": 3, "total": 3}
    assert r["pg"] == {"total": 10, "degraded": 0, "inactive": 0, "undersized": 0}
    assert r["capacity"] == {"total_bytes": 100, "used_bytes": 40, "avail_bytes": 60}
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
