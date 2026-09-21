"""Tests for fivenines_agent.proxmox module."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

import fivenines_agent.proxmox as proxmox_module
from fivenines_agent.cache import TTLCache
from fivenines_agent.proxmox import ProxmoxCollector, _record_failure, proxmox_metrics


@pytest.fixture(autouse=True)
def _fresh_backups_cache(monkeypatch):
    """The backups block is cached at module level per (host, port, token_id)
    for BACKUPS_CACHE_TTL. Every test here builds collectors with the same
    identity, so give each one an empty cache or scenario A's block would be
    served to scenario B."""
    monkeypatch.setattr(proxmox_module, "_backups_cache", TTLCache())


def make_proxmox_mock(
    version=None,
    cluster_status=None,
    cluster_status_raises=False,
    nodes=None,
    nodes_raises=False,
    nodes_raises_from_call=None,
    node_status_by_name=None,
    node_status_raises_for=None,
    qemu_by_node=None,
    qemu_raises_for=None,
    lxc_by_node=None,
    lxc_raises_for=None,
    storage_by_node=None,
    storage_raises_for=None,
    storage_config=None,
    storage_config_raises=False,
    version_raises=False,
    content_by_node_storage=None,
    content_raises_for=None,
    tasks_by_node=None,
    tasks_raises_for=None,
    backup_jobs=None,
    backup_jobs_raises=False,
    not_backed_up=None,
    not_backed_up_raises=False,
    permissions=None,
):
    """Build a MagicMock simulating proxmoxer.ProxmoxAPI chained-call API.

    Each kwarg controls one endpoint. The `_raises_for` variants take a set
    of node names that should raise instead of returning data. `storage_config`
    wires the datacenter /storage endpoint (self.proxmox.storage.get(), distinct
    from the per-node storage below); it defaults to [] so absent-config tests
    get a clean empty datacenter config rather than a bare MagicMock.

    Backups block (#156) endpoints, all defaulting to empty listings so a
    scenario that says nothing about backups gets a well-formed empty block:
    `content_by_node_storage` is {node: {storage: [volumes]}} for
    /nodes/<n>/storage/<s>/content?content=backup and `content_raises_for` a
    set of "node/storage" strings; `tasks_by_node` / `tasks_raises_for` wire
    /nodes/<n>/tasks; `backup_jobs` wires /cluster/backup and `not_backed_up`
    /cluster/backup-info/not-backed-up. `nodes_raises_from_call` = N makes the
    N-th (1-based) and later calls to /nodes raise: collect() lists nodes once
    per section in a fixed order (nodes, vms, lxc, storage, backups), so N=5
    fails only the backups build.
    """
    mock = MagicMock()
    mock._content_calls = []

    if version_raises:
        mock.version.get.side_effect = RuntimeError("version boom")
    elif version is not None:
        mock.version.get.return_value = version

    if cluster_status_raises:
        mock.cluster.status.get.side_effect = RuntimeError("cluster boom")
    elif cluster_status is not None:
        mock.cluster.status.get.return_value = cluster_status

    if nodes_raises:
        mock.nodes.get.side_effect = RuntimeError("nodes boom")
    elif nodes_raises_from_call is not None:
        nodes_calls = []

        def nodes_get():
            nodes_calls.append(1)
            if len(nodes_calls) >= nodes_raises_from_call:
                raise RuntimeError("nodes boom (later call)")
            return nodes

        mock.nodes.get.side_effect = nodes_get
    elif nodes is not None:
        mock.nodes.get.return_value = nodes

    # /cluster/backup (backup job definitions) and
    # /cluster/backup-info/not-backed-up, reached as
    # proxmox.cluster.backup.get() and
    # proxmox.cluster("backup-info")("not-backed-up").get().
    if backup_jobs_raises:
        mock.cluster.backup.get.side_effect = RuntimeError("backup jobs boom")
    else:
        mock.cluster.backup.get.return_value = (
            backup_jobs if backup_jobs is not None else []
        )
    if permissions is not None:
        mock.access.permissions.get.return_value = permissions

    nbu = MagicMock()
    if not_backed_up_raises:
        nbu.get.side_effect = RuntimeError("not-backed-up boom")
    else:
        nbu.get.return_value = not_backed_up if not_backed_up is not None else []
    backup_info = MagicMock(return_value=nbu)
    mock.cluster.return_value = backup_info
    mock._backup_info = backup_info

    # Datacenter /storage config (self.proxmox.storage.get()), distinct from the
    # per-node /nodes/<n>/storage runtime status wired in nodes_call below. This
    # is where the 'pool' property lives, driving the #49 pool enrichment.
    if storage_config_raises:
        mock.storage.get.side_effect = RuntimeError("storage config boom")
    else:
        mock.storage.get.return_value = (
            storage_config if storage_config is not None else []
        )

    node_status_raises_for = node_status_raises_for or set()
    qemu_raises_for = qemu_raises_for or set()
    lxc_raises_for = lxc_raises_for or set()
    storage_raises_for = storage_raises_for or set()
    content_by_node_storage = content_by_node_storage or {}
    content_raises_for = content_raises_for or set()
    tasks_by_node = tasks_by_node or {}
    tasks_raises_for = tasks_raises_for or set()

    node_mocks = {}

    def nodes_call(node_name):
        if node_name not in node_mocks:
            nm = MagicMock()

            if node_name in node_status_raises_for:
                nm.status.get.side_effect = RuntimeError("node status boom")
            elif node_status_by_name and node_name in node_status_by_name:
                nm.status.get.return_value = node_status_by_name[node_name]

            if node_name in qemu_raises_for:
                nm.qemu.get.side_effect = RuntimeError("qemu boom")
            elif qemu_by_node and node_name in qemu_by_node:
                nm.qemu.get.return_value = qemu_by_node[node_name]

            if node_name in lxc_raises_for:
                nm.lxc.get.side_effect = RuntimeError("lxc boom")
            elif lxc_by_node and node_name in lxc_by_node:
                nm.lxc.get.return_value = lxc_by_node[node_name]

            if node_name in storage_raises_for:
                nm.storage.get.side_effect = RuntimeError("storage boom")
            elif storage_by_node and node_name in storage_by_node:
                nm.storage.get.return_value = storage_by_node[node_name]

            # nm.storage(<name>).content.get(content="backup"): the per-storage
            # backup volume listing. side_effect on the callable does not
            # interfere with nm.storage.get (the node's storage list) above.
            def storage_call(storage_name, _node=node_name):
                sm = MagicMock()

                def content_get(**params):
                    mock._content_calls.append((_node, storage_name, params))
                    if f"{_node}/{storage_name}" in content_raises_for:
                        raise RuntimeError("content boom")
                    return content_by_node_storage.get(_node, {}).get(storage_name, [])

                sm.content.get.side_effect = content_get
                return sm

            nm.storage.side_effect = storage_call

            if node_name in tasks_raises_for:
                nm.tasks.get.side_effect = RuntimeError("tasks boom")
            else:
                nm.tasks.get.return_value = tasks_by_node.get(node_name, [])

            node_mocks[node_name] = nm
        return node_mocks[node_name]

    mock.nodes.side_effect = nodes_call
    mock._node_mocks = node_mocks
    return mock


def make_collector(proxmox_mock=None, **init_kwargs):
    """Build a ProxmoxCollector with a mocked ProxmoxAPI."""
    if proxmox_mock is None:
        proxmox_mock = make_proxmox_mock()
    init_kwargs.setdefault("token_id", "root@pam!claude")
    init_kwargs.setdefault("token_secret", "secret123")
    with patch("fivenines_agent.proxmox.ProxmoxAPI", return_value=proxmox_mock):
        collector = ProxmoxCollector(**init_kwargs)
    return collector


def test_proxmox_metrics_no_proxmoxer():
    """T1: proxmox_metrics returns None when proxmoxer is not installed."""
    with patch("fivenines_agent.proxmox.ProxmoxAPI", None):
        assert proxmox_metrics() is None


def test_proxmox_metrics_collector_init_raises():
    """T2: outer try/except in proxmox_metrics catches ProxmoxCollector ctor errors."""
    with patch(
        "fivenines_agent.proxmox.ProxmoxCollector",
        side_effect=RuntimeError("ctor fail"),
    ):
        assert proxmox_metrics(token_id="root@pam!c", token_secret="s") is None


def test_proxmox_metrics_happy_path_returns_dict():
    """T3: proxmox_metrics returns dict on happy path."""
    proxmox_mock = make_proxmox_mock(
        version={"version": "8.1.4"},
        cluster_status=[],
        nodes=[],
    )
    with patch("fivenines_agent.proxmox.ProxmoxAPI", return_value=proxmox_mock):
        result = proxmox_metrics(token_id="root@pam!c", token_secret="s")
    assert result is not None
    assert result["version"] == "8.1.4"
    assert "nodes" in result
    assert "vms" in result
    assert "lxc" in result
    assert "storage" in result
    assert "cluster" in result


def test_proxmox_metrics_forwards_kwargs():
    """T4: proxmox_metrics passes kwargs through to ProxmoxAPI."""
    with patch("fivenines_agent.proxmox.ProxmoxAPI") as mock_api:
        mock_api.return_value.version.get.return_value = {}
        mock_api.return_value.cluster.status.get.return_value = []
        mock_api.return_value.nodes.get.return_value = []
        proxmox_metrics(
            host="10.0.0.1",
            port=8007,
            token_id="root@pam!claude",
            token_secret="s3cret",
            verify_ssl=False,
        )
        mock_api.assert_called_once()
        args, kwargs = mock_api.call_args
        assert args[0] == "10.0.0.1"
        assert kwargs["port"] == 8007
        assert kwargs["user"] == "root@pam"
        assert kwargs["token_name"] == "claude"
        assert kwargs["token_value"] == "s3cret"
        assert kwargs["verify_ssl"] is False


def test_collector_token_id_with_bang_is_split():
    """T5: token_id with `!` is split into user and token_name."""
    with patch("fivenines_agent.proxmox.ProxmoxAPI") as mock_api:
        ProxmoxCollector(host="h", port=1, token_id="root@pam!claude", token_secret="s")
        kwargs = mock_api.call_args.kwargs
        assert kwargs["user"] == "root@pam"
        assert kwargs["token_name"] == "claude"


def test_collector_token_id_without_bang_keeps_full_string():
    """T6: token_id without `!` keeps full string as user, token_name=None."""
    with patch("fivenines_agent.proxmox.ProxmoxAPI") as mock_api:
        ProxmoxCollector(host="h", port=1, token_id="rootonly", token_secret="s")
        kwargs = mock_api.call_args.kwargs
        assert kwargs["user"] == "rootonly"
        assert kwargs["token_name"] is None


def test_collector_no_creds_does_not_connect():
    """T7: missing token_id/secret skips connection, sets self.proxmox=None."""
    with patch("fivenines_agent.proxmox.ProxmoxAPI") as mock_api:
        c = ProxmoxCollector(token_id=None, token_secret=None)
        assert mock_api.call_count == 0
        assert c.proxmox is None


def test_collector_proxmoxapi_raises_sets_proxmox_to_none():
    """T8: ProxmoxAPI raising on construction caught, self.proxmox=None."""
    with patch(
        "fivenines_agent.proxmox.ProxmoxAPI",
        side_effect=RuntimeError("conn boom"),
    ):
        c = ProxmoxCollector(token_id="root@pam!claude", token_secret="s")
        assert c.proxmox is None


def test_collector_verify_ssl_forwarded():
    """T9: verify_ssl is forwarded to ProxmoxAPI."""
    with patch("fivenines_agent.proxmox.ProxmoxAPI") as mock_api:
        ProxmoxCollector(
            token_id="root@pam!claude",
            token_secret="s",
            verify_ssl=False,
        )
        assert mock_api.call_args.kwargs["verify_ssl"] is False


def test_safe_append_skips_none_value():
    """T10: None value is not appended."""
    c = make_collector()
    data = []
    c._safe_append(data, "x", None, {})
    assert data == []


def test_safe_append_includes_value():
    """T11: present value is appended with name/value/labels keys."""
    c = make_collector()
    data = []
    c._safe_append(data, "metric_x", 42, {"vm": "1"})
    assert data == [{"name": "metric_x", "value": 42, "labels": {"vm": "1"}}]


def test_safe_append_catches_append_exception():
    """T12: append exception is caught, no exception escapes."""
    c = make_collector()
    bad_data = MagicMock()
    bad_data.append.side_effect = RuntimeError("append boom")
    c._safe_append(bad_data, "x", 1, {})  # should not raise


def test_collect_returns_none_when_proxmox_is_none():
    """T13: collect returns None when self.proxmox is None."""
    with patch(
        "fivenines_agent.proxmox.ProxmoxAPI",
        side_effect=RuntimeError(),
    ):
        c = ProxmoxCollector(token_id="root@pam!c", token_secret="s")
    assert c.collect() is None


def test_collect_returns_dict_with_eight_keys():
    """T14: collect returns dict with all eight top-level keys (six data keys,
    the 1.10.0 'collection' flags block and the 1.19.0 'backups' block)."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            version={"version": "8"}, cluster_status=[], nodes=[]
        )
    )
    result = c.collect()
    assert set(result.keys()) == {
        "version",
        "cluster",
        "nodes",
        "vms",
        "lxc",
        "storage",
        "backups",
        "collection",
    }


def test_collect_version_failure_does_not_abort():
    """T15: version.get raising does not abort collect."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(version_raises=True, cluster_status=[], nodes=[])
    )
    result = c.collect()
    assert result is not None
    assert result["version"] is None


def test_collect_cluster_failure_does_not_abort():
    """T16: _collect_cluster raising does not abort collect (outer except)."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            version={"version": "8"}, cluster_status=[], nodes=[]
        )
    )
    with patch.object(c, "_collect_cluster", side_effect=RuntimeError("cluster boom")):
        result = c.collect()
    assert result["cluster"] is None
    assert result["nodes"] == []


def test_collect_nodes_failure_does_not_abort():
    """T17: _collect_nodes raising does not abort collect (outer except)."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            version={"version": "8"}, cluster_status=[], nodes=[]
        )
    )
    with patch.object(c, "_collect_nodes", side_effect=RuntimeError("nodes boom")):
        result = c.collect()
    assert result["nodes"] == []


def test_collect_vms_failure_does_not_abort():
    """T18: _collect_vms raising does not abort collect."""
    c = make_collector()
    with patch.object(c, "_collect_vms", side_effect=RuntimeError("vms boom")):
        c.proxmox = make_proxmox_mock(
            version={"version": "8"},
            cluster_status=[],
            nodes=[],
        )
        result = c.collect()
    assert result["vms"] == []


def test_collect_lxc_failure_does_not_abort():
    """T19: _collect_lxc raising does not abort collect."""
    c = make_collector()
    with patch.object(c, "_collect_lxc", side_effect=RuntimeError("lxc boom")):
        c.proxmox = make_proxmox_mock(
            version={"version": "8"},
            cluster_status=[],
            nodes=[],
        )
        result = c.collect()
    assert result["lxc"] == []


def test_collect_storage_failure_does_not_abort():
    """T20: _collect_storage raising does not abort collect."""
    c = make_collector()
    with patch.object(c, "_collect_storage", side_effect=RuntimeError("storage boom")):
        c.proxmox = make_proxmox_mock(
            version={"version": "8"},
            cluster_status=[],
            nodes=[],
        )
        result = c.collect()
    assert result["storage"] == []


def test_collect_version_missing_key_returns_unknown():
    """T21: version response missing 'version' key returns 'unknown'."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(version={}, cluster_status=[], nodes=[])
    )
    result = c.collect()
    assert result["version"] == "unknown"


def test_collect_cluster_quorate_true():
    """T22: quorate=1 returns True."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            cluster_status=[
                {"type": "cluster", "name": "c1", "quorate": 1, "nodes": 2},
                {"type": "node", "online": 1},
                {"type": "node", "online": 1},
            ]
        )
    )
    result = c._collect_cluster()
    assert result["quorate"] is True
    assert result["name"] == "c1"


def test_collect_cluster_quorate_false():
    """T23: quorate=0 returns False."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            cluster_status=[{"type": "cluster", "name": "c1", "quorate": 0, "nodes": 2}]
        )
    )
    result = c._collect_cluster()
    assert result["quorate"] is False


def test_collect_cluster_counts_online_nodes():
    """T24: nodes_online counts entries with online=1."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            cluster_status=[
                {"type": "cluster", "name": "c1", "quorate": 1, "nodes": 0},
                {"type": "node", "online": 1},
                {"type": "node", "online": 0},
                {"type": "node", "online": 1},
            ]
        )
    )
    result = c._collect_cluster()
    assert result["nodes"] == 3
    assert result["nodes_online"] == 2


def test_collect_cluster_no_cluster_entry_returns_none():
    """T25: response with no 'cluster' type entry returns None (single-node)."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(cluster_status=[{"type": "node", "online": 1}])
    )
    assert c._collect_cluster() is None


def test_collect_cluster_exception_returns_none():
    """T26: cluster.status.get raising returns None."""
    c = make_collector(proxmox_mock=make_proxmox_mock(cluster_status_raises=True))
    assert c._collect_cluster() is None


def test_collect_nodes_happy_path():
    """T27: returns list of node dicts on happy path."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            nodes=[
                {
                    "node": "pve1",
                    "status": "online",
                    "cpu": 0.5,
                    "mem": 1000,
                    "maxmem": 2000,
                }
            ],
            node_status_by_name={"pve1": {"uptime": 12345}},
            qemu_by_node={"pve1": []},
            lxc_by_node={"pve1": []},
        )
    )
    nodes = c._collect_nodes()
    assert len(nodes) == 1
    assert nodes[0]["name"] == "pve1"
    assert nodes[0]["uptime"] == 12345
    assert nodes[0]["cpu_usage"] == 0.5
    assert nodes[0]["memory_used"] == 1000
    assert nodes[0]["memory_total"] == 2000


def test_collect_nodes_skips_missing_node_key():
    """T28: nodes whose 'node' key is missing are skipped."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            nodes=[{"status": "online"}, {"node": "pve1"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            qemu_by_node={"pve1": []},
            lxc_by_node={"pve1": []},
        )
    )
    nodes = c._collect_nodes()
    assert [n["name"] for n in nodes] == ["pve1"]


def test_collect_nodes_counts_running_vms():
    """T29: vms_running counts entries with status=running."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            nodes=[{"node": "pve1"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            qemu_by_node={
                "pve1": [
                    {"vmid": 1, "status": "running"},
                    {"vmid": 2, "status": "stopped"},
                    {"vmid": 3, "status": "running"},
                ]
            },
            lxc_by_node={"pve1": []},
        )
    )
    nodes = c._collect_nodes()
    assert nodes[0]["vms_running"] == 2


def test_collect_nodes_counts_running_lxc():
    """T30: lxc_running counts entries with status=running."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            nodes=[{"node": "pve1"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            qemu_by_node={"pve1": []},
            lxc_by_node={
                "pve1": [
                    {"vmid": 100, "status": "running"},
                    {"vmid": 101, "status": "stopped"},
                ]
            },
        )
    )
    nodes = c._collect_nodes()
    assert nodes[0]["lxc_running"] == 1


def test_collect_nodes_qemu_failure_yields_zero_count():
    """T31: qemu enumeration failure inside node yields vms_running=0."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            nodes=[{"node": "pve1"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            qemu_raises_for={"pve1"},
            lxc_by_node={"pve1": []},
        )
    )
    nodes = c._collect_nodes()
    assert nodes[0]["vms_running"] == 0


def test_collect_nodes_lxc_failure_yields_zero_count():
    """T32: lxc enumeration failure inside node yields lxc_running=0."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            nodes=[{"node": "pve1"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            qemu_by_node={"pve1": []},
            lxc_raises_for={"pve1"},
        )
    )
    nodes = c._collect_nodes()
    assert nodes[0]["lxc_running"] == 0


def test_collect_nodes_per_node_failure_isolates():
    """T33: per-node status fetch failure logs and continues to next node."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            nodes=[{"node": "pve1"}, {"node": "pve2"}],
            node_status_by_name={"pve2": {"uptime": 99}},
            node_status_raises_for={"pve1"},
            qemu_by_node={"pve1": [], "pve2": []},
            lxc_by_node={"pve1": [], "pve2": []},
        )
    )
    nodes = c._collect_nodes()
    assert [n["name"] for n in nodes] == ["pve2"]


def test_collect_nodes_outer_failure_returns_empty():
    """T34: outer nodes.get failure returns empty list."""
    c = make_collector(proxmox_mock=make_proxmox_mock(nodes_raises=True))
    assert c._collect_nodes() == []


def test_collect_vms_calls_qemu_get_with_full_one():
    """T35 [REGRESSION]: qemu.get is called with full=1 to populate disk I/O."""
    pmock = make_proxmox_mock(nodes=[{"node": "pve1"}], qemu_by_node={"pve1": []})
    c = make_collector(proxmox_mock=pmock)
    c._collect_vms()
    pmock._node_mocks["pve1"].qemu.get.assert_called_with(full=1)


def test_collect_vms_happy_path_shape():
    """T36: VM dict has all expected keys."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        qemu_by_node={
            "pve1": [
                {
                    "vmid": 100,
                    "name": "web",
                    "status": "running",
                    "cpu": 0.1,
                    "mem": 1000,
                    "maxmem": 2000,
                    "diskread": 11,
                    "diskwrite": 22,
                    "netin": 33,
                    "netout": 44,
                    "uptime": 555,
                }
            ]
        },
    )
    c = make_collector(proxmox_mock=pmock)
    vms = c._collect_vms()
    assert len(vms) == 1
    assert set(vms[0].keys()) == {
        "vmid",
        "name",
        "node",
        "status",
        "cpu_usage",
        "memory_used",
        "memory_max",
        "disk_read",
        "disk_write",
        "net_in",
        "net_out",
        "uptime",
    }


def test_collect_vms_diskread_null_coerces_to_zero():
    """T37 [BUG]: diskread=None (the customer's symptom) becomes disk_read=0."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        qemu_by_node={
            "pve1": [
                {
                    "vmid": 100,
                    "name": "web",
                    "status": "running",
                    "diskread": None,
                    "diskwrite": None,
                }
            ]
        },
    )
    c = make_collector(proxmox_mock=pmock)
    vms = c._collect_vms()
    assert vms[0]["disk_read"] == 0
    assert vms[0]["disk_write"] == 0


def test_collect_vms_diskread_value_passes_through():
    """T38: non-null diskread preserved in output."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        qemu_by_node={
            "pve1": [
                {
                    "vmid": 100,
                    "name": "web",
                    "status": "running",
                    "diskread": 12345,
                }
            ]
        },
    )
    c = make_collector(proxmox_mock=pmock)
    assert c._collect_vms()[0]["disk_read"] == 12345


@pytest.mark.parametrize(
    "field_in,field_out",
    [
        ("cpu", "cpu_usage"),
        ("mem", "memory_used"),
        ("maxmem", "memory_max"),
        ("diskread", "disk_read"),
        ("diskwrite", "disk_write"),
        ("netin", "net_in"),
        ("netout", "net_out"),
        ("uptime", "uptime"),
    ],
)
def test_collect_vms_null_fields_coerce_to_zero(field_in, field_out):
    """T39: every numeric VM field, when null in API, becomes 0 in output."""
    vm = {"vmid": 100, "name": "x", "status": "running"}
    vm[field_in] = None
    pmock = make_proxmox_mock(nodes=[{"node": "pve1"}], qemu_by_node={"pve1": [vm]})
    c = make_collector(proxmox_mock=pmock)
    assert c._collect_vms()[0][field_out] == 0


def test_collect_vms_skips_missing_vmid():
    """T40: VM with missing vmid key is filtered out."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        qemu_by_node={
            "pve1": [
                {"name": "no-vmid", "status": "running"},
                {"vmid": 100, "name": "ok", "status": "running"},
            ]
        },
    )
    c = make_collector(proxmox_mock=pmock)
    vms = c._collect_vms()
    assert [v["vmid"] for v in vms] == [100]


def test_collect_vms_missing_name_falls_back():
    """T41: missing name falls back to f'vm-{vmid}'."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        qemu_by_node={"pve1": [{"vmid": 42, "status": "stopped"}]},
    )
    c = make_collector(proxmox_mock=pmock)
    assert c._collect_vms()[0]["name"] == "vm-42"


def test_collect_vms_per_node_failure_isolates():
    """T42: one node throws, other still collected."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}, {"node": "pve2"}],
        qemu_raises_for={"pve1"},
        qemu_by_node={"pve2": [{"vmid": 200, "name": "ok", "status": "running"}]},
    )
    c = make_collector(proxmox_mock=pmock)
    vms = c._collect_vms()
    assert [v["vmid"] for v in vms] == [200]


def test_collect_vms_outer_failure_returns_empty():
    """T43: outer nodes.get failure returns empty list."""
    c = make_collector(proxmox_mock=make_proxmox_mock(nodes_raises=True))
    assert c._collect_vms() == []


def test_collect_vms_multi_node_iteration():
    """T44: VMs from all healthy nodes are present in result."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}, {"node": "pve2"}],
        qemu_by_node={
            "pve1": [{"vmid": 1, "name": "a", "status": "running"}],
            "pve2": [{"vmid": 2, "name": "b", "status": "running"}],
        },
    )
    c = make_collector(proxmox_mock=pmock)
    vms = c._collect_vms()
    assert sorted(v["vmid"] for v in vms) == [1, 2]


def test_collect_vms_node_info_missing_node_key_skipped():
    """T45: node_info entries missing 'node' key are skipped."""
    pmock = make_proxmox_mock(
        nodes=[{"status": "online"}, {"node": "pve1"}],
        qemu_by_node={"pve1": [{"vmid": 1, "name": "x", "status": "running"}]},
    )
    c = make_collector(proxmox_mock=pmock)
    vms = c._collect_vms()
    assert [v["vmid"] for v in vms] == [1]


def test_collect_lxc_calls_get_with_no_kwargs():
    """T46 [REGRESSION]: lxc.get called WITHOUT full=1 (the parameter doesn't
    exist on the LXC endpoint)."""
    pmock = make_proxmox_mock(nodes=[{"node": "pve1"}], lxc_by_node={"pve1": []})
    c = make_collector(proxmox_mock=pmock)
    c._collect_lxc()
    pmock._node_mocks["pve1"].lxc.get.assert_called_with()


def test_collect_lxc_happy_path_shape():
    """T47: CT dict has all expected keys."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        lxc_by_node={
            "pve1": [
                {
                    "vmid": 200,
                    "name": "ct",
                    "status": "running",
                    "cpu": 0.1,
                    "mem": 1000,
                    "maxmem": 2000,
                    "diskread": 11,
                    "diskwrite": 22,
                    "netin": 33,
                    "netout": 44,
                    "uptime": 555,
                }
            ]
        },
    )
    c = make_collector(proxmox_mock=pmock)
    cts = c._collect_lxc()
    assert set(cts[0].keys()) == {
        "vmid",
        "name",
        "node",
        "status",
        "cpu_usage",
        "memory_used",
        "memory_max",
        "disk_read",
        "disk_write",
        "net_in",
        "net_out",
        "uptime",
    }


def test_collect_lxc_diskread_null_coerces_to_zero():
    """T48: LXC diskread=None becomes disk_read=0."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        lxc_by_node={
            "pve1": [
                {
                    "vmid": 200,
                    "name": "x",
                    "status": "running",
                    "diskread": None,
                }
            ]
        },
    )
    c = make_collector(proxmox_mock=pmock)
    assert c._collect_lxc()[0]["disk_read"] == 0


def test_collect_lxc_diskread_value_passes_through():
    """T49: LXC non-null diskread preserved."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        lxc_by_node={
            "pve1": [
                {
                    "vmid": 200,
                    "name": "x",
                    "status": "running",
                    "diskread": 999,
                }
            ]
        },
    )
    c = make_collector(proxmox_mock=pmock)
    assert c._collect_lxc()[0]["disk_read"] == 999


@pytest.mark.parametrize(
    "field_in,field_out",
    [
        ("cpu", "cpu_usage"),
        ("mem", "memory_used"),
        ("maxmem", "memory_max"),
        ("diskread", "disk_read"),
        ("diskwrite", "disk_write"),
        ("netin", "net_in"),
        ("netout", "net_out"),
        ("uptime", "uptime"),
    ],
)
def test_collect_lxc_null_fields_coerce_to_zero(field_in, field_out):
    """T50: every numeric LXC field, when null, becomes 0."""
    ct = {"vmid": 200, "name": "x", "status": "running"}
    ct[field_in] = None
    pmock = make_proxmox_mock(nodes=[{"node": "pve1"}], lxc_by_node={"pve1": [ct]})
    c = make_collector(proxmox_mock=pmock)
    assert c._collect_lxc()[0][field_out] == 0


def test_collect_lxc_skips_missing_vmid():
    """T51: LXC entry without vmid is filtered out."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        lxc_by_node={
            "pve1": [
                {"name": "no-vmid", "status": "running"},
                {"vmid": 200, "name": "ok", "status": "running"},
            ]
        },
    )
    c = make_collector(proxmox_mock=pmock)
    assert [c["vmid"] for c in c._collect_lxc()] == [200]


def test_collect_lxc_missing_name_falls_back():
    """T52: LXC missing name falls back to f'ct-{vmid}'."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        lxc_by_node={"pve1": [{"vmid": 7, "status": "stopped"}]},
    )
    c = make_collector(proxmox_mock=pmock)
    assert c._collect_lxc()[0]["name"] == "ct-7"


def test_collect_lxc_per_node_failure_isolates():
    """T53: one node throws, other still collected."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}, {"node": "pve2"}],
        lxc_raises_for={"pve1"},
        lxc_by_node={"pve2": [{"vmid": 300, "name": "ok", "status": "running"}]},
    )
    c = make_collector(proxmox_mock=pmock)
    assert [ct["vmid"] for ct in c._collect_lxc()] == [300]


def test_collect_lxc_outer_failure_returns_empty():
    """T54: outer nodes.get failure returns empty list."""
    c = make_collector(proxmox_mock=make_proxmox_mock(nodes_raises=True))
    assert c._collect_lxc() == []


def test_collect_lxc_multi_node_iteration():
    """T55: CTs from all healthy nodes are present in result."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}, {"node": "pve2"}],
        lxc_by_node={
            "pve1": [{"vmid": 1, "name": "a", "status": "running"}],
            "pve2": [{"vmid": 2, "name": "b", "status": "running"}],
        },
    )
    c = make_collector(proxmox_mock=pmock)
    assert sorted(ct["vmid"] for ct in c._collect_lxc()) == [1, 2]


def test_collect_lxc_node_info_missing_node_key_skipped():
    """T56: node_info entries missing 'node' key are skipped."""
    pmock = make_proxmox_mock(
        nodes=[{"status": "online"}, {"node": "pve1"}],
        lxc_by_node={"pve1": [{"vmid": 1, "name": "x", "status": "running"}]},
    )
    c = make_collector(proxmox_mock=pmock)
    assert [ct["vmid"] for ct in c._collect_lxc()] == [1]


def test_collect_storage_happy_path_shape():
    """T57: storage dict has all expected keys."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        storage_by_node={
            "pve1": [
                {
                    "storage": "local",
                    "type": "dir",
                    "total": 1000,
                    "used": 500,
                    "avail": 500,
                    "active": 1,
                }
            ]
        },
    )
    c = make_collector(proxmox_mock=pmock)
    pools = c._collect_storage()
    assert set(pools[0].keys()) == {
        "name",
        "node",
        "type",
        "total",
        "used",
        "available",
        "active",
    }


def test_collect_storage_active_bool_coercion():
    """T58: active=1 -> True; active=0 -> False."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        storage_by_node={
            "pve1": [
                {"storage": "a", "active": 1},
                {"storage": "b", "active": 0},
            ]
        },
    )
    c = make_collector(proxmox_mock=pmock)
    pools = c._collect_storage()
    by_name = {p["name"]: p for p in pools}
    assert by_name["a"]["active"] is True
    assert by_name["b"]["active"] is False


def test_collect_storage_skips_missing_storage_name():
    """T59: storage entry without 'storage' key is filtered out."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        storage_by_node={
            "pve1": [
                {"type": "dir", "total": 100},
                {"storage": "ok", "type": "dir"},
            ]
        },
    )
    c = make_collector(proxmox_mock=pmock)
    assert [p["name"] for p in c._collect_storage()] == ["ok"]


def test_collect_storage_per_node_failure_isolates():
    """T60: one node throws, other still collected."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}, {"node": "pve2"}],
        storage_raises_for={"pve1"},
        storage_by_node={"pve2": [{"storage": "okstorage", "type": "dir"}]},
    )
    c = make_collector(proxmox_mock=pmock)
    assert [p["name"] for p in c._collect_storage()] == ["okstorage"]


def test_collect_storage_outer_failure_returns_empty():
    """T61: outer nodes.get failure returns empty list."""
    c = make_collector(proxmox_mock=make_proxmox_mock(nodes_raises=True))
    assert c._collect_storage() == []


def test_collect_storage_node_info_missing_node_key_skipped():
    """T62: node_info entries missing 'node' key are skipped."""
    pmock = make_proxmox_mock(
        nodes=[{"status": "online"}, {"node": "pve1"}],
        storage_by_node={"pve1": [{"storage": "ok", "type": "dir"}]},
    )
    c = make_collector(proxmox_mock=pmock)
    assert [p["name"] for p in c._collect_storage()] == ["ok"]


@pytest.mark.parametrize(
    "field_in,field_out",
    [("total", "total"), ("used", "used"), ("avail", "available")],
)
def test_collect_storage_null_fields_coerce_to_zero(field_in, field_out):
    """T63: storage total/used/avail null becomes 0."""
    s = {"storage": "x", "type": "dir"}
    s[field_in] = None
    pmock = make_proxmox_mock(nodes=[{"node": "pve1"}], storage_by_node={"pve1": [s]})
    c = make_collector(proxmox_mock=pmock)
    assert c._collect_storage()[0][field_out] == 0


# --- error-path normalization (1.9.0) ---------------------------------------


def test_collect_unreachable_returns_none():
    """T64 [1.9.0]: version.get() AND the node-listing probe both raising
    (whole-module unreachable / auth failure after lazy token-auth construction)
    collapses to None, so the collector emits data['proxmox']=null instead of an
    empty-but-shaped dict a healthy idle node could never actually produce."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(version_raises=True, nodes_raises=True)
    )
    assert c.collect() is None


def test_collect_version_denied_but_nodes_reachable_returns_dict():
    """T65 [1.9.0]: a restricted token whose /version is denied but whose node
    listing works is reachable -- collect() still returns a payload (version
    null) rather than being misread as unreachable and dropped."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            version_raises=True,
            cluster_status=[],
            nodes=[{"node": "pve1"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            qemu_by_node={"pve1": []},
            lxc_by_node={"pve1": []},
        )
    )
    result = c.collect()
    assert result is not None
    assert result["version"] is None
    assert [n["name"] for n in result["nodes"]] == ["pve1"]


def test_collect_reachability_probe_only_when_version_fails():
    """T66 [1.9.0]: the node-listing reachability probe is issued only when
    version.get() fails. A healthy collection (version OK) does NOT probe, so the
    healthy-path API call pattern is unchanged; the version-denied path adds
    exactly one node listing (the probe)."""
    healthy = make_proxmox_mock(version={"version": "8"}, cluster_status=[], nodes=[])
    make_collector(proxmox_mock=healthy).collect()

    # Both collectors share the backups cache identity; without a reset the
    # second one would serve the cached block and skip its own node listing.
    proxmox_module._backups_cache = TTLCache()
    denied = make_proxmox_mock(version_raises=True, cluster_status=[], nodes=[])
    make_collector(proxmox_mock=denied).collect()

    assert denied.nodes.get.call_count == healthy.nodes.get.call_count + 1


def test_proxmox_metrics_unreachable_returns_none_end_to_end():
    """T67 [1.9.0]: the entry point returns None on an unreachable API, so
    collect_metrics stores data['proxmox']=None (the sole unreachable signal)."""
    mock = make_proxmox_mock(version_raises=True, nodes_raises=True)
    with patch("fivenines_agent.proxmox.ProxmoxAPI", return_value=mock):
        assert proxmox_metrics(token_id="root@pam!c", token_secret="s") is None


# --- explicit collection flags block (1.10.0) -------------------------------
#
# data['proxmox'].collection = {reachable, cluster_ok, nodes_ok, guests_ok,
# storage_ok, error}. Each *_ok is True iff every API call backing that section
# succeeded (guests_ok covers both the qemu and lxc loops); the server reads
# these instead of inferring completeness from the payload shape. reachable is
# always True inside a non-null payload -- an unreachable API returns None (see
# the 1.9.0 tests above), never a payload with reachable:false.


def _collection(result):
    """Pull the collection block, asserting the payload is non-null first."""
    assert result is not None
    return result["collection"]


def test_record_failure_noop_when_collection_none():
    """T68: _record_failure is a no-op when collection is None, so every
    _collect_* helper stays callable in isolation (as the unit tests above do)
    without a flags block to thread through."""
    assert _record_failure(None, "nodes_ok", "ignored") is None


def test_collection_all_ok_on_healthy_collection():
    """T69: every section succeeding sets all flags True and error None."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            version={"version": "8"},
            cluster_status=[
                {"type": "cluster", "name": "c1", "quorate": 1, "nodes": 1},
                {"type": "node", "online": 1},
            ],
            nodes=[{"node": "pve1"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            qemu_by_node={"pve1": []},
            lxc_by_node={"pve1": []},
            storage_by_node={"pve1": []},
        )
    )
    assert _collection(c.collect()) == {
        "reachable": True,
        "cluster_ok": True,
        "nodes_ok": True,
        "guests_ok": True,
        "storage_ok": True,
        "error": None,
    }


def test_collection_cluster_ok_false_when_cluster_status_raises():
    """T70: /cluster/status raising sets cluster_ok False (cluster stays null)
    and records the error; the node/guest/storage sections are unaffected."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            version={"version": "8"},
            cluster_status_raises=True,
            nodes=[{"node": "pve1"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            qemu_by_node={"pve1": []},
            lxc_by_node={"pve1": []},
            storage_by_node={"pve1": []},
        )
    )
    result = c.collect()
    assert result["cluster"] is None
    coll = _collection(result)
    assert coll["cluster_ok"] is False
    assert coll["nodes_ok"] is True
    assert coll["guests_ok"] is True
    assert coll["storage_ok"] is True
    assert coll["error"] == "cluster status query failed"


def test_collection_standalone_keeps_cluster_ok_true():
    """T71 [DISAMBIGUATION]: a standalone node (no cluster-type entry) leaves
    cluster:null but cluster_ok True -- the flag the server uses to tell it
    apart from a failed /cluster/status (cluster:null, cluster_ok False)."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            version={"version": "8"},
            cluster_status=[{"type": "node", "online": 1}],
            nodes=[{"node": "pve1"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            qemu_by_node={"pve1": []},
            lxc_by_node={"pve1": []},
            storage_by_node={"pve1": []},
        )
    )
    result = c.collect()
    assert result["cluster"] is None
    coll = _collection(result)
    assert coll["cluster_ok"] is True
    assert coll["error"] is None


def test_collection_nodes_ok_false_when_node_status_raises():
    """T72: a per-node status fetch raising drops that node and sets nodes_ok
    False; the error names the node. guests_ok/storage_ok stay True here, so
    the failure is attributed to the node section alone."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            version={"version": "8"},
            cluster_status=[],
            nodes=[{"node": "pve1"}, {"node": "pve2"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            node_status_raises_for={"pve2"},
            qemu_by_node={"pve1": [], "pve2": []},
            lxc_by_node={"pve1": [], "pve2": []},
            storage_by_node={"pve1": [], "pve2": []},
        )
    )
    result = c.collect()
    assert [n["name"] for n in result["nodes"]] == ["pve1"]
    coll = _collection(result)
    assert coll["nodes_ok"] is False
    assert coll["guests_ok"] is True
    assert coll["storage_ok"] is True
    assert coll["error"] == "node pve2: status query failed"


def test_collection_node_listing_failure_marks_all_node_derived_flags():
    """T73: the /nodes listing itself raising fails the node, guest, and
    storage sections together (each re-lists nodes). reachability still holds
    via the version call, and cluster_ok is untouched."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            version={"version": "8"},
            cluster_status=[],
            nodes_raises=True,
        )
    )
    coll = _collection(c.collect())
    assert coll["reachable"] is True
    assert coll["cluster_ok"] is True
    assert coll["nodes_ok"] is False
    assert coll["guests_ok"] is False
    assert coll["storage_ok"] is False
    assert coll["error"] == "node listing failed"


def test_collection_guests_ok_false_when_qemu_raises():
    """T74: a per-node qemu listing raising sets guests_ok False; nodes_ok and
    storage_ok are unaffected."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            version={"version": "8"},
            cluster_status=[],
            nodes=[{"node": "pve1"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            qemu_raises_for={"pve1"},
            lxc_by_node={"pve1": []},
            storage_by_node={"pve1": []},
        )
    )
    coll = _collection(c.collect())
    assert coll["guests_ok"] is False
    assert coll["nodes_ok"] is True
    assert coll["storage_ok"] is True
    assert coll["error"] == "node pve1: qemu query failed"


def test_collection_guests_ok_false_when_lxc_raises():
    """T75: a per-node lxc listing raising also sets guests_ok False -- the flag
    covers both guest loops (qemu and lxc)."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            version={"version": "8"},
            cluster_status=[],
            nodes=[{"node": "pve1"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            qemu_by_node={"pve1": []},
            lxc_raises_for={"pve1"},
            storage_by_node={"pve1": []},
        )
    )
    coll = _collection(c.collect())
    assert coll["guests_ok"] is False
    assert coll["nodes_ok"] is True
    assert coll["storage_ok"] is True
    assert coll["error"] == "node pve1: lxc query failed"


def test_collection_storage_ok_false_in_isolation():
    """T76: a lone storage failure sets ONLY storage_ok False -- nodes_ok and
    guests_ok stay True (issue #80's example shape). This is what shape
    inference cannot express: an empty storage array here means 'query failed',
    not 'no storages exist'."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            version={"version": "8"},
            cluster_status=[],
            nodes=[{"node": "pve1"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            qemu_by_node={"pve1": []},
            lxc_by_node={"pve1": []},
            storage_raises_for={"pve1"},
        )
    )
    coll = _collection(c.collect())
    assert coll["storage_ok"] is False
    assert coll["nodes_ok"] is True
    assert coll["guests_ok"] is True
    assert coll["cluster_ok"] is True
    assert coll["error"] == "node pve1: storage query failed"


def test_collection_error_is_first_failure_in_section_order():
    """T77: with failures in multiple sections, error is the FIRST one in
    collect() order (cluster before storage), not the last -- and later
    failures still flip their own flag."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            version={"version": "8"},
            cluster_status_raises=True,
            nodes=[{"node": "pve1"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            qemu_by_node={"pve1": []},
            lxc_by_node={"pve1": []},
            storage_raises_for={"pve1"},
        )
    )
    coll = _collection(c.collect())
    assert coll["cluster_ok"] is False
    assert coll["storage_ok"] is False
    assert coll["error"] == "cluster status query failed"


def test_collection_reachable_true_when_version_denied_but_nodes_listed():
    """T78: reachable is True even when /version is denied, as long as the node
    listing probe succeeds -- the payload exists, so reachable is stated True
    (version is null, but that is carried by result['version'], not a flag)."""
    c = make_collector(
        proxmox_mock=make_proxmox_mock(
            version_raises=True,
            cluster_status=[],
            nodes=[{"node": "pve1"}],
            node_status_by_name={"pve1": {"uptime": 1}},
            qemu_by_node={"pve1": []},
            lxc_by_node={"pve1": []},
            storage_by_node={"pve1": []},
        )
    )
    result = c.collect()
    assert result["version"] is None
    assert _collection(result)["reachable"] is True


# --- storage 'pool' enrichment (#49 ZFS<->Proxmox join key) ------------------
#
# Each storage entry OPTIONALLY carries 'pool', read from the datacenter
# /storage config (self.proxmox.storage.get()), which the per-node runtime
# status endpoint does not return. It is the join key the server uses to
# correlate a PVE storage to host-local ZFS pool health: for a zfspool the zpool
# root is pool.split('/')[0]. Enrichment is additive and best-effort -- absent
# for non-pool types, and a /storage failure degrades to no 'pool' WITHOUT
# flipping storage_ok.


def test_collect_storage_pool_enrichment_sets_zfspool_omits_dir():
    """T79 [#49]: a zfspool storage gets 'pool' from the datacenter /storage
    config; a dir storage (no pool property) does not."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        storage_by_node={
            "pve1": [
                {"storage": "local", "type": "dir", "active": 1},
                {"storage": "local-zfs", "type": "zfspool", "active": 1},
            ]
        },
        storage_config=[
            {"storage": "local", "type": "dir"},
            {"storage": "local-zfs", "type": "zfspool", "pool": "rpool/data"},
        ],
    )
    c = make_collector(proxmox_mock=pmock)
    by_name = {p["name"]: p for p in c._collect_storage()}
    assert by_name["local-zfs"]["pool"] == "rpool/data"
    assert "pool" not in by_name["local"]


def test_collect_storage_pool_omitted_when_absent_from_config():
    """T80 [#49]: a storage present in per-node runtime status but absent from
    the datacenter /storage config gets no 'pool' (omitted, never null)."""
    pmock = make_proxmox_mock(
        nodes=[{"node": "pve1"}],
        storage_by_node={
            "pve1": [{"storage": "local-zfs", "type": "zfspool", "active": 1}]
        },
        storage_config=[],
    )
    c = make_collector(proxmox_mock=pmock)
    pools = c._collect_storage()
    assert "pool" not in pools[0]


def test_collect_storage_degrades_when_storage_config_fails():
    """T81 [#49]: /storage (datacenter config) raising degrades to no 'pool' on
    any entry but still collects storage and does NOT flip storage_ok -- pool
    enrichment is best-effort and off the collection flags block."""
    pmock = make_proxmox_mock(
        version={"version": "8"},
        cluster_status=[],
        nodes=[{"node": "pve1"}],
        node_status_by_name={"pve1": {"uptime": 1}},
        qemu_by_node={"pve1": []},
        lxc_by_node={"pve1": []},
        storage_by_node={
            "pve1": [{"storage": "local-zfs", "type": "zfspool", "active": 1}]
        },
        storage_config_raises=True,
    )
    c = make_collector(proxmox_mock=pmock)
    result = c.collect()
    assert [p["name"] for p in result["storage"]] == ["local-zfs"]
    assert "pool" not in result["storage"][0]
    assert result["collection"]["storage_ok"] is True


def test_storage_config_map_builds_and_skips_unnamed():
    """T82 [#49]: _storage_config_map indexes /storage entries by storage id and
    skips entries with no 'storage' key."""
    pmock = make_proxmox_mock(
        storage_config=[
            {"storage": "local-zfs", "type": "zfspool", "pool": "rpool/data"},
            {"type": "dir"},  # no storage id -> skipped
        ],
    )
    c = make_collector(proxmox_mock=pmock)
    config_map = c._storage_config_map()
    assert set(config_map) == {"local-zfs"}
    assert config_map["local-zfs"]["pool"] == "rpool/data"


def test_storage_config_map_degrades_on_failure():
    """T83 [#49]: _storage_config_map swallows a /storage failure and returns an
    empty map (best-effort, never raises)."""
    pmock = make_proxmox_mock(storage_config_raises=True)
    c = make_collector(proxmox_mock=pmock)
    assert c._storage_config_map() == {}


# --- cross-repo contract (fivenines-server) ---------------------------------
#
# Shared fixture tests/fixtures/proxmox_contract_payload.json is asserted on
# both sides. Here: for each scenario, proxmox_metrics() built from the mock
# spec in scenario["api"] must equal scenario["payload"], with only
# proxmoxer.ProxmoxAPI mocked -- so the whole connect -> collect -> payload
# pipeline is pinned. On fivenines-server: spec posts each scenario["payload"]
# under data["proxmox"] and asserts the cluster-scope ingester reads the right
# completeness flags. As of agent 1.10.0 the payload carries an explicit
# ceph-style 'collection' block (reachable/cluster_ok/nodes_ok/guests_ok/
# storage_ok/error); the server prefers it over shape inference. Both the flags
# AND the underlying shapes must stay pinned (shape is the pre-1.10.0 fallback).
# Change payloads only in lockstep with the server's byte-identical fixture copy.

_CONTRACT_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "proxmox_contract_payload.json"
)

with open(_CONTRACT_FIXTURE_PATH) as _f:
    _CONTRACT = json.load(_f)

_CONTRACT_SCENARIOS = _CONTRACT["scenarios"]

# Top-level and per-entry key sets the server's shape inference depends on. A
# rename or dropped key must fail HERE, not silently zero a server-side metric.
_PAYLOAD_KEYS = {
    "version",
    "cluster",
    "nodes",
    "vms",
    "lxc",
    "storage",
    "backups",
    "collection",
}
_COLLECTION_KEYS = {
    "reachable",
    "cluster_ok",
    "nodes_ok",
    "guests_ok",
    "storage_ok",
    "error",
}
_CLUSTER_KEYS = {"name", "quorate", "nodes", "nodes_online"}
_NODE_KEYS = {
    "name",
    "status",
    "cpu_usage",
    "memory_used",
    "memory_total",
    "uptime",
    "vms_running",
    "lxc_running",
}
_GUEST_KEYS = {
    "vmid",
    "name",
    "node",
    "status",
    "cpu_usage",
    "memory_used",
    "memory_max",
    "disk_read",
    "disk_write",
    "net_in",
    "net_out",
    "uptime",
}
_STORAGE_KEYS = {"name", "node", "type", "total", "used", "available", "active"}
# 'pool' (#49) is the only key a storage entry may carry beyond the base 7 --
# present for pool-backed types (zfspool/rbd/cephfs), omitted otherwise.
_STORAGE_OPTIONAL_KEYS = {"pool"}
# backups block (#156, agent 1.19.0+)
_BACKUPS_KEYS = {"age_s", "guest_backups", "tasks", "jobs", "not_backed_up", "errors"}
_GUEST_BACKUP_KEYS = {
    "vmid",
    "storage",
    "node",
    "latest_ctime",
    "latest_volid",
    "latest_size",
    "count",
}
# Present only when the storage reports them (PBS: verification + encrypted).
_GUEST_BACKUP_OPTIONAL_KEYS = {"verification", "protected", "encrypted"}
_TASK_KEYS = {"upid", "node", "id", "starttime", "endtime", "status", "user"}
_JOB_KEYS = {
    "id",
    "enabled",
    "schedule",
    "storage",
    "vmid",
    "all",
    "exclude",
    "pool",
    "node",
    "mode",
    "comment",
    "next_run",
}
_NOT_BACKED_UP_KEYS = {"vmid", "name", "type"}
_BACKUP_ERROR_KEYS = {"scope", "node", "storage", "message"}
_BACKUP_ERROR_SCOPES = {"storage", "tasks", "jobs", "not_backed_up", "cap"}


@pytest.mark.parametrize("scenario_name", sorted(_CONTRACT_SCENARIOS))
def test_contract_fixture_scenarios(scenario_name):
    """SHARED FIXTURE (cross-repo contract): each scenario's payload is exactly
    what proxmox_metrics() emits under data['proxmox'] for that Proxmox API
    state, with only proxmoxer mocked."""
    scenario = _CONTRACT_SCENARIOS[scenario_name]
    mock = make_proxmox_mock(**scenario["api"])
    with patch("fivenines_agent.proxmox.ProxmoxAPI", return_value=mock):
        out = proxmox_metrics(token_id="root@pam!contract", token_secret="secret")
    assert out == scenario["payload"]


@pytest.mark.parametrize("scenario_name", sorted(_CONTRACT_SCENARIOS))
def test_contract_payload_key_sets(scenario_name):
    """Pin the payload key contract across every non-null scenario, so a
    rename/drop breaks the build instead of the server's inference."""
    payload = _CONTRACT_SCENARIOS[scenario_name]["payload"]
    if payload is None:  # 'unreachable' -> data["proxmox"] is null
        return
    assert set(payload) == _PAYLOAD_KEYS
    assert set(payload["collection"]) == _COLLECTION_KEYS
    if payload["cluster"] is not None:
        assert set(payload["cluster"]) == _CLUSTER_KEYS
    for node in payload["nodes"]:
        assert set(node) == _NODE_KEYS
    for guest in payload["vms"] + payload["lxc"]:
        assert set(guest) == _GUEST_KEYS
    for storage in payload["storage"]:
        keys = set(storage)
        assert _STORAGE_KEYS <= keys
        assert keys - _STORAGE_KEYS <= _STORAGE_OPTIONAL_KEYS
    backups = payload["backups"]
    if backups is None:  # 'backups_block_failed' -> node listing failed
        return
    assert set(backups) == _BACKUPS_KEYS
    assert isinstance(backups["age_s"], int) and backups["age_s"] >= 0
    for entry in backups["guest_backups"]:
        keys = set(entry)
        assert _GUEST_BACKUP_KEYS <= keys
        assert keys - _GUEST_BACKUP_KEYS <= _GUEST_BACKUP_OPTIONAL_KEYS
        assert entry["latest_ctime"] is not None and entry["vmid"] is not None
        if "verification" in entry:
            assert set(entry["verification"]) == {"state", "upid"}
    for task in backups["tasks"]:
        assert set(task) == _TASK_KEYS
    for job in backups["jobs"]:
        assert set(job) == _JOB_KEYS
    for guest in backups["not_backed_up"]:
        assert set(guest) == _NOT_BACKED_UP_KEYS
    for error in backups["errors"]:
        assert set(error) == _BACKUP_ERROR_KEYS
        assert error["scope"] in _BACKUP_ERROR_SCOPES


def test_contract_reachable_signal():
    """reachable <=> payload is not None. Only 'unreachable' yields a null
    payload; every other scenario is reachable."""
    for name, scenario in _CONTRACT_SCENARIOS.items():
        assert (scenario["payload"] is None) == (name == "unreachable")


def test_contract_nodes_ok_signal():
    """The server's nodes_ok signal is len(nodes) == cluster.nodes_online. It
    holds in the fully-healthy cluster and is deliberately violated by the
    mid-loop node timeout (pve2 online in corosync but dropped from nodes)."""
    healthy = _CONTRACT_SCENARIOS["quorate_cluster"]["payload"]
    assert healthy["cluster"]["nodes_online"] == len(healthy["nodes"]) == 3

    partial = _CONTRACT_SCENARIOS["partial_node_timeout"]["payload"]
    assert partial["cluster"]["nodes_online"] == 3
    assert len(partial["nodes"]) == 2  # pve2 dropped mid-loop -> nodes_ok=false


def test_contract_standalone_cluster_is_null():
    """A reachable standalone node reports cluster:null but is NOT unreachable:
    version present and nodes non-empty. Pins the shape the server must not
    confuse with a null payload."""
    standalone = _CONTRACT_SCENARIOS["standalone"]["payload"]
    assert standalone is not None
    assert standalone["cluster"] is None
    assert standalone["version"] is not None
    assert len(standalone["nodes"]) == 1


def test_contract_collection_reachable_matches_non_null_payload():
    """collection.reachable is True in every non-null payload; the only
    unreachable signal remains a null payload ('unreachable')."""
    for name, scenario in _CONTRACT_SCENARIOS.items():
        payload = scenario["payload"]
        if payload is None:
            assert name == "unreachable"
        else:
            assert payload["collection"]["reachable"] is True


def test_contract_collection_disambiguates_standalone_from_cluster_failure():
    """The whole point of #80: 'standalone' and 'cluster_fetch_failed' both emit
    cluster:null, and the explicit cluster_ok flag is what separates them --
    a distinction the pre-1.10.0 shape inference could not make."""
    standalone = _CONTRACT_SCENARIOS["standalone"]["payload"]
    failed = _CONTRACT_SCENARIOS["cluster_fetch_failed"]["payload"]
    assert standalone["cluster"] is None
    assert failed["cluster"] is None
    assert standalone["collection"]["cluster_ok"] is True
    assert failed["collection"]["cluster_ok"] is False
    assert failed["collection"]["error"] == "cluster status query failed"


def test_contract_collection_storage_ok_independent():
    """'storage_query_failed' pins storage_ok independence: only storage_ok is
    false while nodes_ok/guests_ok/cluster_ok stay true (issue #80's example)."""
    coll = _CONTRACT_SCENARIOS["storage_query_failed"]["payload"]["collection"]
    assert coll["storage_ok"] is False
    assert coll["nodes_ok"] is True
    assert coll["guests_ok"] is True
    assert coll["cluster_ok"] is True
    assert coll["error"] == "node pve2: storage query failed"


def test_contract_storage_pool_join_key():
    """#49: the 'standalone' scenario pins the storage 'pool' join key -- a
    zfspool storage carries pool='rpool/data' (its zpool root 'rpool' is what the
    server joins to host-local ZFS pool health), while dir/lvmthin carry no pool.
    This is the field proxmox_storages.name (the PVE storage ID 'local-zfs')
    could never provide."""
    storage = _CONTRACT_SCENARIOS["standalone"]["payload"]["storage"]
    by_name = {s["name"]: s for s in storage}
    assert by_name["local-zfs"]["pool"] == "rpool/data"
    assert by_name["local-zfs"]["pool"].split("/")[0] == "rpool"
    assert "pool" not in by_name["local"]
    assert "pool" not in by_name["local-lvm"]


def test_contract_backups_key_present_in_every_non_null_payload():
    """#156 rule 1, level one: 'key absent' is reserved for agents older than
    1.19.0. Every non-null payload this agent emits carries the key, even
    when the block itself is null."""
    for name, scenario in _CONTRACT_SCENARIOS.items():
        payload = scenario["payload"]
        if payload is not None:
            assert "backups" in payload, name


def test_contract_backups_shared_once_local_per_node():
    """backups_ok: the shared PBS storage appears once per guest with
    node:null (listed from pve1 only -- pve2's decoy vm 999 never shows), the
    local dir storage once per node with node set."""
    entries = _CONTRACT_SCENARIOS["backups_ok"]["payload"]["backups"]["guest_backups"]
    pbs = [e for e in entries if e["storage"] == "pbs-main"]
    local = [e for e in entries if e["storage"] == "local"]
    assert sorted(e["vmid"] for e in pbs) == [100, 101]
    assert all(e["node"] is None for e in pbs)
    assert {(e["vmid"], e["node"]) for e in local} == {(100, "pve1"), (101, "pve2")}
    assert 999 not in [e["vmid"] for e in entries]
    vm100_pbs = next(e for e in pbs if e["vmid"] == 100)
    assert vm100_pbs["count"] == 2
    assert vm100_pbs["latest_ctime"] == 1789950000
    assert vm100_pbs["verification"] == {
        "state": "ok",
        "upid": "UPID:pbs:00002A44:0000F3A1:00000000:68CEEB80:verificationjob:main:root@pam:",
    }
    assert vm100_pbs["encrypted"] is True and vm100_pbs["protected"] is False
    ct101_local = next(e for e in local if e["vmid"] == 101)
    assert ct101_local["count"] == 3 and ct101_local["latest_ctime"] == 1789863600
    assert "verification" not in ct101_local and "encrypted" not in ct101_local


def test_contract_backups_status_verbatim_and_id_null():
    """Task status reaches the wire verbatim ('OK', 'WARNINGS: 1'); a
    multi-guest job task has id null."""
    tasks = _CONTRACT_SCENARIOS["backups_ok"]["payload"]["backups"]["tasks"]
    assert [t["status"] for t in tasks] == ["OK", "WARNINGS: 1"]
    assert all(t["id"] is None for t in tasks)
    assert [t["node"] for t in tasks] == ["pve1", "pve2"]


def test_contract_backups_jobs_and_not_backed_up():
    backups = _CONTRACT_SCENARIOS["backups_ok"]["payload"]["backups"]
    assert backups["jobs"] == [
        {
            "id": "backup-6b2f1a7c-e1d3",
            "enabled": True,
            "schedule": "02:00",
            "storage": "pbs-main",
            "vmid": "100,101",
            "all": False,
            "exclude": None,
            "pool": None,
            "node": None,
            "mode": "snapshot",
            "comment": None,
            "next_run": 1790035200,
        }
    ]
    assert backups["not_backed_up"] == [{"vmid": 105, "name": "scratch", "type": "qemu"}]
    assert backups["errors"] == []


def test_contract_backups_partial_names_storage_and_keeps_others():
    """backups_storage_partial: the failed storage is named in errors[] and
    vm 100's backup on the other storage is still present; collection is
    untouched."""
    payload = _CONTRACT_SCENARIOS["backups_storage_partial"]["payload"]
    backups = payload["backups"]
    assert backups["errors"] == [
        {
            "scope": "storage",
            "node": "pve1",
            "storage": "pbs-main",
            "message": "content listing failed: content boom",
        }
    ]
    assert [(e["vmid"], e["storage"]) for e in backups["guest_backups"]] == [(100, "local")]
    assert payload["collection"] == {
        "reachable": True,
        "cluster_ok": True,
        "nodes_ok": True,
        "guests_ok": True,
        "storage_ok": True,
        "error": None,
    }


def test_contract_backups_block_failed_is_null_and_collection_untouched():
    payload = _CONTRACT_SCENARIOS["backups_block_failed"]["payload"]
    assert payload["backups"] is None
    assert payload["collection"]["error"] is None
    assert all(payload["collection"][k] for k in ("cluster_ok", "nodes_ok", "guests_ok", "storage_ok"))
    assert payload["storage"]  # the flagged sections were read fine


def test_contract_backups_capped_is_announced():
    backups = _CONTRACT_SCENARIOS["backups_capped"]["payload"]["backups"]
    assert len(backups["tasks"]) == proxmox_module.MAX_TASKS_PER_NODE == 50
    assert backups["errors"] == [
        {
            "scope": "cap",
            "node": "pve1",
            "storage": None,
            "message": "tasks capped at 50: 1 dropped",
        }
    ]


# --- backups block (#156) unit tests -----------------------------------------


class _FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def monotonic(self):
        return self.t


def _volume(vmid, ctime, volid=None, **extra):
    v = {"vmid": vmid, "ctime": ctime, "volid": volid or f"s:backup/vm/{vmid}/{ctime}"}
    v.update(extra)
    return v


def _dir_storage(name, active=1, **extra):
    row = {"storage": name, "type": "dir", "content": "backup,iso", "active": active}
    row.update(extra)
    return row


def _one_node_mock(**kwargs):
    kwargs.setdefault("version", {"version": "8"})
    kwargs.setdefault("cluster_status", [])
    kwargs.setdefault("nodes", [{"node": "pve1"}])
    return make_proxmox_mock(**kwargs)


def test_scrub_str_sanitizes_and_caps():
    scrub = proxmox_module._scrub_str
    assert scrub(None) is None
    assert scrub("a\x00b\x00") == "ab"
    assert "\ud800" not in scrub("x\ud800y")  # lone surrogate replaced
    assert scrub(100) == "100"
    assert len(scrub("z" * 10_000)) == proxmox_module._BACKUP_FIELD_MAX_LEN
    assert scrub("abc", max_len=2) == "ab"


def test_log_safe_bounds_input_before_redact():
    """F1 (adversarial): a proxmoxer exception's str() carries the full HTTP
    error body; redact() must see a PREFIX-BOUNDED string (like the wire path),
    never an unbounded customer blob, or it is a CPU/mem sink on the watchdog
    loop. Assert redact() is handed at most _ERROR_PRE_REDACT_MAX_LEN chars."""
    with patch.object(proxmox_module, "redact", side_effect=lambda t: t) as m:
        proxmox_module._log_safe("z" * 100000)
    assert len(m.call_args[0][0]) == proxmox_module._ERROR_PRE_REDACT_MAX_LEN


def test_node_name_is_scrubbed_on_the_wire():
    """F6 (adversarial): every emitted string is bounded/NUL-scrubbed, including
    the node name -- a compromised PVE could return it oversized or with control
    chars. Covers both wire sites: tasks[].node and guest_backups[].node."""
    mock = _one_node_mock(tasks_by_node={"n\x00x": [{"upid": "U", "status": "OK"}]})
    tasks = make_collector(proxmox_mock=mock)._collect_vzdump_tasks(["n\x00x"], [])
    assert tasks[0]["node"] == "nx"
    mock2 = _one_node_mock(
        storage_by_node={"n\x00x": [_dir_storage("local")]},
        content_by_node_storage={"n\x00x": {"local": [_volume(100, 1)]}},
    )
    entries = make_collector(proxmox_mock=mock2)._collect_guest_backups(["n\x00x"], [])
    assert entries[0]["node"] == "nx"


def test_log_safe_collapses_control_chars_and_redacts():
    """Security: customer-controlled text on the log path gets the same guard
    as the wire path -- newlines/control chars collapse to spaces (no journal
    log-forging) and secrets are redacted."""
    safe = proxmox_module._log_safe
    assert "\n" not in safe("line1\nline2\r\tx")
    assert safe("a\nb") == "a b"
    assert safe("secret=AKIAIOSFODNN7EXAMPLE") == "secret=[REDACTED]"
    assert safe(RuntimeError("boom\n403")) == "boom 403"
    assert len(safe("a b " * 2000)) == proxmox_module._ERROR_MAX_LEN


def test_has_backup_read_priv_checks_storage_and_ancestors():
    """#156: only a token with Datastore.Allocate (on the storage or an ancestor
    path) can trust an empty backup read; audit-only cannot; perms None (fetch
    failed) degrades to True (best-effort read)."""
    have = proxmox_module._has_backup_read_priv
    assert have(None, "s") is True  # perms unavailable -> degrade
    assert have({}, "s") is False
    assert have({"/storage/s": {"Datastore.Allocate": 1}}, "s") is True
    assert have({"/storage": {"Datastore.Allocate": 1}}, "s") is True
    assert have({"/": {"Datastore.Allocate": 1}}, "s") is True
    assert have({"/storage/other": {"Datastore.Allocate": 1}}, "s") is False
    # PVEAuditor's actual set: audit privileges only -> cannot see backups.
    audit_only = {"/storage/s": {"Datastore.Audit": 1, "VM.Audit": 1}}
    assert have(audit_only, "s") is False


def test_effective_permissions_is_best_effort():
    ok = _one_node_mock(permissions={"/storage/local": {"Datastore.Allocate": 1}})
    assert make_collector(proxmox_mock=ok)._effective_permissions() == {
        "/storage/local": {"Datastore.Allocate": 1}
    }
    bad = _one_node_mock()
    bad.access.permissions.get.side_effect = RuntimeError("boom")
    assert make_collector(proxmox_mock=bad)._effective_permissions() is None
    nonlist = _one_node_mock()
    nonlist.access.permissions.get.return_value = ["not", "a", "dict"]
    assert make_collector(proxmox_mock=nonlist)._effective_permissions() is None


def test_guest_backups_local_without_priv_is_unknown_no_read():
    """An audit-only token: the storage is reported unknown WITHOUT a content
    read (the read would be a filtered empty, a false all-clear)."""
    mock = _one_node_mock(
        storage_by_node={"pve1": [_dir_storage("local")]},
        content_by_node_storage={"pve1": {"local": [_volume(100, 1)]}},
        permissions={"/storage/local": {"Datastore.Audit": 1}},
    )
    errors = []
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(["pve1"], errors)
    assert entries == []
    assert errors == [
        {
            "scope": "storage",
            "node": "pve1",
            "storage": "local",
            "message": proxmox_module._NO_BACKUP_PRIV_MESSAGE,
        }
    ]
    # the filtered read is never even issued
    assert mock._content_calls == []


def test_guest_backups_local_with_priv_reads_normally():
    mock = _one_node_mock(
        storage_by_node={"pve1": [_dir_storage("local")]},
        content_by_node_storage={"pve1": {"local": [_volume(100, 1)]}},
        permissions={"/": {"Datastore.Allocate": 1}},  # granted at the root
    )
    errors = []
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(["pve1"], errors)
    assert errors == []
    assert [(e["vmid"], e["storage"]) for e in entries] == [(100, "local")]
    assert len(mock._content_calls) == 1


def test_guest_backups_shared_without_priv_unknown_once():
    """A shared storage without the privilege is reported unknown ONCE (node
    null), no content read, and later nodes do not re-error."""
    shared = {"storage": "pbs", "type": "pbs", "content": "backup", "shared": 1, "active": 1}
    mock = _one_node_mock(
        nodes=[{"node": "pve1"}, {"node": "pve2"}],
        storage_by_node={"pve1": [shared], "pve2": [shared]},
        content_by_node_storage={"pve1": {"pbs": [_volume(100, 1)]}},
        permissions={"/storage/pbs": {"Datastore.Audit": 1}},
    )
    errors = []
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(
        ["pve1", "pve2"], errors
    )
    assert entries == []
    assert errors == [
        {
            "scope": "storage",
            "node": None,
            "storage": "pbs",
            "message": proxmox_module._NO_BACKUP_PRIV_MESSAGE,
        }
    ]
    assert mock._content_calls == []


def test_scrub_csv_truncates_at_comma_never_splits_an_id():
    """A job's vmid/exclude is a comma-list; a char cap must not split an ID
    (",224" -> ",22" would name a guest that was never configured)."""
    csv = proxmox_module._scrub_csv
    assert csv(None) is None
    assert csv("100,101") == "100,101"
    # Over the cap: truncate at the last comma, keeping only whole ids.
    ids = ",".join(str(n) for n in range(100, 400))  # > 500 chars
    out = csv(ids)
    assert len(out) <= proxmox_module._BACKUP_FIELD_MAX_LEN
    assert all(part.isdigit() for part in out.split(","))  # no split id
    assert not out.endswith(",")
    # A single over-long token with no comma before the cap: hard char cut.
    out2 = csv("9" * 800)
    assert len(out2) == proxmox_module._BACKUP_FIELD_MAX_LEN


def test_build_backups_block_null_when_node_listing_not_a_list():
    """A non-list node envelope is a build failure -> backups:null, never a
    block of empty arrays the server would read as 'no backups anywhere'."""
    mock = _one_node_mock()
    mock.nodes.get.return_value = {"not": "a list"}
    assert make_collector(proxmox_mock=mock)._build_backups_block() is None


def test_build_backups_block_caps_the_errors_array(monkeypatch):
    """A degraded cluster must not emit an unbounded errors[]; past MAX_ERRORS
    the tail is dropped and one 'cap' error records how many."""
    monkeypatch.setattr(proxmox_module, "MAX_ERRORS", 2)
    mock = _one_node_mock(
        nodes=[{"node": "a"}, {"node": "b"}, {"node": "c"}],
        storage_raises_for={"a", "b", "c"},
    )
    _, block = make_collector(proxmox_mock=mock)._build_backups_block()
    assert len(block["errors"]) == 2
    assert block["errors"][-1] == {
        "scope": "cap",
        "node": None,
        "storage": None,
        "message": "errors capped at 2: 2 dropped",
    }


def test_jobs_non_list_response_is_a_scoped_error():
    mock = _one_node_mock()
    mock.cluster.backup.get.return_value = {"not": "a list"}
    errors = []
    assert make_collector(proxmox_mock=mock)._collect_backup_jobs(errors) == []
    assert errors == [
        {
            "scope": "jobs",
            "node": None,
            "storage": None,
            "message": "unexpected response shape (not a list)",
        }
    ]


def test_not_backed_up_non_list_response_is_a_scoped_error():
    mock = _one_node_mock()
    mock._backup_info.return_value.get.return_value = "nope"
    errors = []
    assert make_collector(proxmox_mock=mock)._collect_not_backed_up(errors) == []
    assert errors == [
        {
            "scope": "not_backed_up",
            "node": None,
            "storage": None,
            "message": "unexpected response shape (not a list)",
        }
    ]


def test_tasks_non_list_response_is_a_scoped_error():
    mock = _one_node_mock()
    mock.nodes("pve1").tasks.get.return_value = {"not": "a list"}
    errors = []
    assert make_collector(proxmox_mock=mock)._collect_vzdump_tasks(["pve1"], errors) == []
    assert errors == [
        {
            "scope": "tasks",
            "node": "pve1",
            "storage": None,
            "message": "unexpected response shape (not a list)",
        }
    ]


def test_backups_cache_invalidated_by_verify_ssl_change():
    """A TLS-posture change must not serve the pre-change block: verify_ssl is
    part of the cache key."""
    a = make_collector(proxmox_mock=_one_node_mock(), verify_ssl=True)
    b = make_collector(proxmox_mock=_one_node_mock(), verify_ssl=False)
    assert a._backups_cache_key != b._backups_cache_key
    assert a._backups_cache_key[-1] is True and b._backups_cache_key[-1] is False


def test_as_int_and_as_bool_coercions():
    as_int, as_bool = proxmox_module._as_int, proxmox_module._as_bool
    assert as_int(True) is None and as_int(None) is None
    assert as_int("12") == 12 and as_int(1.9) == 1
    assert as_int("x") is None and as_int([]) is None and as_int(float("nan")) is None
    assert as_bool("0") is False and as_bool("") is False and as_bool(" 0 ") is False
    assert as_bool("1") is True and as_bool("ab:cd:ef") is True  # PBS fingerprint
    assert as_bool(0) is False and as_bool(1) is True


def test_holds_backups_filters_content_and_disabled():
    holds = proxmox_module._holds_backups
    assert holds({"content": "images,rootdir"}) is False
    assert holds({"content": "iso,backup"}) is True
    assert holds({}) is True  # older PVE without the field: list anyway
    assert holds({"content": "backup", "enabled": 0}) is False
    assert holds({"content": "backup", "enabled": 1}) is True


def test_backup_error_bounds_and_scrubs_message():
    errors = []
    proxmox_module._backup_error(errors, "tasks", "x\x00" * 3000, node="n")
    # str[:2000] -> redact -> _scrub_str slices to 500 (incl NUL) then drops NUL.
    assert errors == [
        {"scope": "tasks", "node": "n", "storage": None, "message": "x" * 250}
    ]


def test_guest_backups_aggregates_latest_per_guest_regardless_of_order():
    """Latest ctime wins whatever the listing order; count covers every
    volume; size falls back to approximate-size; the PBS-only keys are
    re-derived from the winning volume, never inherited from a loser."""
    mock = _one_node_mock(
        storage_by_node={"pve1": [_dir_storage("local")]},
        content_by_node_storage={
            "pve1": {
                "local": [
                    _volume(100, 300, size=3, verification={"state": "ok", "upid": "U1"}, protected=1),
                    _volume(100, 100, size=1),
                    _volume(100, 200, size=2),
                    _volume(101, 50, **{"approximate-size": 7}),
                ]
            }
        },
    )
    c = make_collector(proxmox_mock=mock)
    errors = []
    entries = c._collect_guest_backups(["pve1"], errors)
    assert errors == []
    assert entries == [
        {
            "vmid": 100,
            "storage": "local",
            "node": "pve1",
            "latest_ctime": 300,
            "latest_volid": "s:backup/vm/100/300",
            "latest_size": 3,
            "count": 3,
            "verification": {"state": "ok", "upid": "U1"},
            "protected": True,
        },
        {
            "vmid": 101,
            "storage": "local",
            "node": "pve1",
            "latest_ctime": 50,
            "latest_volid": "s:backup/vm/101/50",
            "latest_size": 7,
            "count": 1,
        },
    ]


def test_guest_backups_newer_volume_drops_stale_optional_keys():
    mock = _one_node_mock(
        storage_by_node={"pve1": [_dir_storage("local")]},
        content_by_node_storage={
            "pve1": {
                "local": [
                    _volume(100, 100, encrypted="1", protected=1, verification={"state": "ok", "upid": "U"}),
                    _volume(100, 200),
                ]
            }
        },
    )
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(["pve1"], [])
    assert entries[0]["latest_ctime"] == 200
    assert not ({"encrypted", "protected", "verification"} & set(entries[0]))


def test_guest_backups_content_query_and_skips():
    """The content listing asks for content=backup; non-dict volumes, non-dict
    storage rows, rows without a name and storages that cannot hold backups are
    skipped silently, but a dict volume missing vmid/ctime is COUNTED and the
    storage flagged incomplete (so its unmatched guests read unknown, not a
    false "never backed up")."""
    mock = _one_node_mock(
        storage_by_node={
            "pve1": [
                "garbage",
                {"type": "dir", "content": "backup", "active": 1},
                {"storage": "local-lvm", "type": "lvmthin", "content": "images", "active": 1},
                _dir_storage("local"),
            ]
        },
        content_by_node_storage={
            "pve1": {
                "local": [
                    "garbage",
                    {"vmid": 100, "volid": "no-ctime"},
                    {"ctime": 5, "volid": "no-vmid"},
                    {"vmid": True, "ctime": 5},
                    _volume(100, 10),
                ]
            }
        },
    )
    errors = []
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(["pve1"], errors)
    assert errors == [
        {
            "scope": "storage",
            "node": "pve1",
            "storage": "local",
            "message": "3 backup volume(s) skipped (missing vmid or ctime)",
        }
    ]
    assert [(e["vmid"], e["count"]) for e in entries] == [(100, 1)]
    assert mock._content_calls == [("pve1", "local", {"content": "backup"})]


def test_guest_backups_shared_listed_once_from_first_active_node():
    """pve1 sees the shared storage inactive, pve2 active: listed from pve2
    only, emitted with node:null, no error."""
    shared = {"storage": "pbs", "type": "pbs", "content": "backup", "shared": 1}
    mock = _one_node_mock(
        nodes=[{"node": "pve1"}, {"node": "pve2"}, {"node": "pve3"}],
        storage_by_node={
            "pve1": [dict(shared, active=0)],
            "pve2": [dict(shared, active=1)],
            "pve3": [dict(shared, active=1)],
        },
        content_by_node_storage={
            "pve2": {"pbs": [_volume(100, 10)]},
            "pve3": {"pbs": [_volume(999, 10)]},
        },
    )
    errors = []
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(
        ["pve1", "pve2", "pve3"], errors
    )
    assert errors == []
    assert entries == [
        {
            "vmid": 100,
            "storage": "pbs",
            "node": None,
            "latest_ctime": 10,
            "latest_volid": "s:backup/vm/100/10",
            "latest_size": None,
            "count": 1,
        }
    ]
    assert [(n, s) for n, s, _ in mock._content_calls] == [("pve2", "pbs")]


def test_guest_backups_shared_inactive_everywhere_is_an_error_not_a_listing():
    shared = {"storage": "pbs", "type": "pbs", "content": "backup", "shared": 1, "active": 0}
    mock = _one_node_mock(
        nodes=[{"node": "pve1"}, {"node": "pve2"}],
        storage_by_node={"pve1": [shared], "pve2": [shared]},
    )
    errors = []
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(["pve1", "pve2"], errors)
    assert entries == []
    assert errors == [
        {
            "scope": "storage",
            "node": None,
            "storage": "pbs",
            "message": "shared storage not active on any node",
        }
    ]
    assert mock._content_calls == []


def test_guest_backups_local_inactive_is_an_error_not_a_listing():
    mock = _one_node_mock(storage_by_node={"pve1": [_dir_storage("usb", active=0)]})
    errors = []
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(["pve1"], errors)
    assert entries == []
    assert errors == [
        {
            "scope": "storage",
            "node": "pve1",
            "storage": "usb",
            "message": "storage not active on this node",
        }
    ]
    assert mock._content_calls == []


def test_guest_backups_shared_flag_falls_back_to_datacenter_config():
    """A per-node row without `shared` takes the flag from /storage."""
    row = {"storage": "nfs", "type": "nfs", "content": "backup", "active": 1}
    mock = _one_node_mock(
        nodes=[{"node": "pve1"}, {"node": "pve2"}],
        storage_by_node={"pve1": [row], "pve2": [row]},
        storage_config=[{"storage": "nfs", "type": "nfs", "shared": 1}],
        content_by_node_storage={"pve1": {"nfs": [_volume(100, 1)]}, "pve2": {"nfs": [_volume(100, 1)]}},
    )
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(["pve1", "pve2"], [])
    assert [(e["storage"], e["node"]) for e in entries] == [("nfs", None)]
    assert len(mock._content_calls) == 1


def test_guest_backups_node_storage_listing_failure_is_scoped_and_isolated():
    mock = _one_node_mock(
        nodes=[{"node": "pve1"}, {"node": "pve2"}],
        storage_by_node={"pve2": [_dir_storage("local")]},
        storage_raises_for={"pve1"},
        content_by_node_storage={"pve2": {"local": [_volume(100, 1)]}},
    )
    errors = []
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(["pve1", "pve2"], errors)
    assert [(e["vmid"], e["node"]) for e in entries] == [(100, "pve2")]
    assert errors == [
        {
            "scope": "storage",
            "node": "pve1",
            "storage": None,
            "message": "storage listing failed: storage boom",
        }
    ]


def test_guest_backups_non_list_content_is_a_scoped_error():
    """A non-list content envelope (a malformed response or a proxmoxer quirk)
    must be a scoped error, never iterated into a silent empty result -- and it
    leaves no half-counted entry behind."""
    mock = _one_node_mock(storage_by_node={"pve1": [_dir_storage("local")]})
    nm = mock.nodes("pve1")

    def storage_call(name):
        sm = MagicMock()
        sm.content.get.side_effect = lambda **_: {"not": "a list"}
        return sm

    nm.storage.side_effect = storage_call
    errors = []
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(["pve1"], errors)
    assert entries == []
    assert errors == [
        {
            "scope": "storage",
            "node": "pve1",
            "storage": "local",
            "message": "unexpected response shape (not a list)",
        }
    ]


def test_guest_backups_shared_content_failure_retries_on_next_active_node():
    """A shared storage is marked done only on a SUCCESSFUL listing, so a
    transient failure on the first active node lets the next active node retry
    it -- a healthy alternative is never suppressed (the design's "never a false
    not-backed-up")."""
    shared = {"storage": "pbs", "type": "pbs", "content": "backup", "shared": 1, "active": 1}
    mock = _one_node_mock(
        nodes=[{"node": "pve1"}, {"node": "pve2"}],
        storage_by_node={"pve1": [shared], "pve2": [shared]},
        content_raises_for={"pve1/pbs"},
        content_by_node_storage={"pve2": {"pbs": [_volume(100, 10)]}},
    )
    errors = []
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(
        ["pve1", "pve2"], errors
    )
    # pve1's failure is recorded, but pve2 retries and its data is used (node:null).
    assert [(e["vmid"], e["storage"], e["node"]) for e in entries] == [(100, "pbs", None)]
    assert errors == [
        {
            "scope": "storage",
            "node": "pve1",
            "storage": "pbs",
            "message": "content listing failed: content boom",
        }
    ]
    assert [(n, st) for n, st, _ in mock._content_calls] == [("pve1", "pbs"), ("pve2", "pbs")]


def test_guest_backups_cap_is_announced(monkeypatch):
    monkeypatch.setattr(proxmox_module, "MAX_GUEST_BACKUPS", 2)
    mock = _one_node_mock(
        storage_by_node={"pve1": [_dir_storage("local")]},
        content_by_node_storage={
            "pve1": {"local": [_volume(102, 1), _volume(100, 1), _volume(101, 1)]}
        },
    )
    errors = []
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(["pve1"], errors)
    assert [e["vmid"] for e in entries] == [100, 101]  # sorted, then trimmed
    assert errors == [
        {
            "scope": "cap",
            "node": None,
            "storage": None,
            "message": "guest_backups capped at 2: 1 dropped",
        }
    ]


def test_tasks_query_shape_and_id_rule():
    mock = _one_node_mock(
        tasks_by_node={
            "pve1": [
                {"upid": "U1", "id": "", "starttime": 1, "endtime": 2, "status": "job errors", "user": "root@pam"},
                {"upid": "U2", "id": "100", "starttime": "3", "endtime": None, "status": "OK", "user": "root@pam"},
                "garbage",
            ]
        }
    )
    errors = []
    tasks = make_collector(proxmox_mock=mock)._collect_vzdump_tasks(["pve1"], errors)
    assert errors == []
    assert tasks == [
        {"upid": "U1", "node": "pve1", "id": None, "starttime": 1, "endtime": 2, "status": "job errors", "user": "root@pam"},
        {"upid": "U2", "node": "pve1", "id": "100", "starttime": 3, "endtime": None, "status": "OK", "user": "root@pam"},
    ]
    mock.nodes("pve1").tasks.get.assert_called_once_with(typefilter="vzdump", limit=51)


def test_tasks_status_is_scrubbed_and_capped():
    mock = _one_node_mock(
        tasks_by_node={"pve1": [{"upid": "U", "status": "bad\x00" + "e" * 1000}]}
    )
    tasks = make_collector(proxmox_mock=mock)._collect_vzdump_tasks(["pve1"], [])
    assert tasks[0]["status"].startswith("bade")
    assert "\x00" not in tasks[0]["status"]
    assert len(tasks[0]["status"]) == 499  # 500-char slice, NUL removed


def test_tasks_failure_is_scoped_per_node_and_isolated():
    mock = _one_node_mock(
        nodes=[{"node": "pve1"}, {"node": "pve2"}],
        tasks_raises_for={"pve1"},
        tasks_by_node={"pve2": [{"upid": "U", "status": "OK"}]},
    )
    errors = []
    tasks = make_collector(proxmox_mock=mock)._collect_vzdump_tasks(["pve1", "pve2"], errors)
    assert [t["node"] for t in tasks] == ["pve2"]
    assert errors == [
        {"scope": "tasks", "node": "pve1", "storage": None, "message": "task listing failed: tasks boom"}
    ]


def test_tasks_cap_is_announced(monkeypatch):
    monkeypatch.setattr(proxmox_module, "MAX_TASKS_PER_NODE", 1)
    mock = _one_node_mock(tasks_by_node={"pve1": [{"upid": "A"}, {"upid": "B"}]})
    errors = []
    tasks = make_collector(proxmox_mock=mock)._collect_vzdump_tasks(["pve1"], errors)
    assert [t["upid"] for t in tasks] == ["A"]
    assert errors == [
        {"scope": "cap", "node": "pve1", "storage": None, "message": "tasks capped at 1: 1 dropped"}
    ]


def test_jobs_shape_legacy_schedule_and_defaults():
    mock = _one_node_mock(
        backup_jobs=[
            {"id": "j1", "schedule": "mon..fri 02:00", "storage": "s", "vmid": 100, "all": 1, "exclude": "101", "pool": "p", "node": "pve1", "mode": "stop", "comment": "c", "next-run": 5, "mailto": "x"},
            {"id": "j2", "dow": "mon,tue", "starttime": "03:00"},
            {"id": "j3", "starttime": "04:00", "enabled": 0},
            "garbage",
        ]
    )
    errors = []
    jobs = make_collector(proxmox_mock=mock)._collect_backup_jobs(errors)
    assert errors == []
    assert jobs[0] == {
        "id": "j1",
        "enabled": True,
        "schedule": "mon..fri 02:00",
        "storage": "s",
        "vmid": "100",
        "all": True,
        "exclude": "101",
        "pool": "p",
        "node": "pve1",
        "mode": "stop",
        "comment": "c",
        "next_run": 5,
    }
    assert jobs[1]["schedule"] == "mon,tue 03:00" and jobs[1]["enabled"] is True
    assert jobs[2]["schedule"] == "04:00" and jobs[2]["enabled"] is False
    assert jobs[2]["all"] is False and jobs[2]["next_run"] is None
    assert len(jobs) == 3


def test_jobs_failure_and_cap(monkeypatch):
    errors = []
    jobs = make_collector(proxmox_mock=_one_node_mock(backup_jobs_raises=True))._collect_backup_jobs(errors)
    assert jobs == []
    assert errors == [
        {"scope": "jobs", "node": None, "storage": None, "message": "backup job listing failed: backup jobs boom"}
    ]

    monkeypatch.setattr(proxmox_module, "MAX_BACKUP_JOBS", 1)
    errors = []
    jobs = make_collector(
        proxmox_mock=_one_node_mock(backup_jobs=[{"id": "a"}, {"id": "b"}])
    )._collect_backup_jobs(errors)
    assert [j["id"] for j in jobs] == ["a"]
    assert errors == [
        {"scope": "cap", "node": None, "storage": None, "message": "jobs capped at 1: 1 dropped"}
    ]


def test_not_backed_up_endpoint_path_and_shape():
    mock = _one_node_mock(
        not_backed_up=[
            {"vmid": 105, "name": "scratch", "type": "qemu"},
            {"vmid": "106", "name": None, "type": "lxc"},
            {"name": "no-vmid", "type": "qemu"},
            "garbage",
        ]
    )
    errors = []
    guests = make_collector(proxmox_mock=mock)._collect_not_backed_up(errors)
    assert errors == []
    assert guests == [
        {"vmid": 105, "name": "scratch", "type": "qemu"},
        {"vmid": 106, "name": None, "type": "lxc"},
    ]
    mock.cluster.assert_called_with("backup-info")
    mock._backup_info.assert_called_with("not-backed-up")


def test_not_backed_up_failure_and_cap(monkeypatch):
    errors = []
    guests = make_collector(
        proxmox_mock=_one_node_mock(not_backed_up_raises=True)
    )._collect_not_backed_up(errors)
    assert guests == []
    assert errors == [
        {
            "scope": "not_backed_up",
            "node": None,
            "storage": None,
            "message": "not-backed-up listing failed: not-backed-up boom",
        }
    ]

    monkeypatch.setattr(proxmox_module, "MAX_NOT_BACKED_UP", 1)
    errors = []
    guests = make_collector(
        proxmox_mock=_one_node_mock(not_backed_up=[{"vmid": 1}, {"vmid": 2}])
    )._collect_not_backed_up(errors)
    assert [g["vmid"] for g in guests] == [1]
    assert errors[0]["message"] == "not_backed_up capped at 1: 1 dropped"


def test_build_backups_block_skips_malformed_node_entries():
    mock = _one_node_mock(
        nodes=["garbage", {"status": "online"}, {"node": "pve1"}],
        storage_by_node={"pve1": []},
    )
    computed_at, block = make_collector(proxmox_mock=mock)._build_backups_block()
    assert block["errors"] == [] and block["guest_backups"] == []
    assert mock.nodes.call_args_list[-1].args == ("pve1",)


def test_collect_backups_null_when_node_listing_fails_collection_untouched():
    """Rule 1 middle level + rule 2: the backups build is the 5th node
    listing; when it fails the block is null and every flag stays True."""
    mock = _one_node_mock(nodes_raises_from_call=5, storage_by_node={"pve1": [_dir_storage("local")]})
    result = make_collector(proxmox_mock=mock).collect()
    assert result["backups"] is None
    assert result["collection"] == {
        "reachable": True,
        "cluster_ok": True,
        "nodes_ok": True,
        "guests_ok": True,
        "storage_ok": True,
        "error": None,
    }


def test_collect_backups_partial_leaves_collection_untouched():
    mock = _one_node_mock(
        storage_by_node={"pve1": [_dir_storage("local")]},
        content_raises_for={"pve1/local"},
        tasks_raises_for={"pve1"},
        backup_jobs_raises=True,
        not_backed_up_raises=True,
    )
    result = make_collector(proxmox_mock=mock).collect()
    assert [e["scope"] for e in result["backups"]["errors"]] == [
        "storage",
        "tasks",
        "jobs",
        "not_backed_up",
    ]
    assert result["collection"]["error"] is None
    assert result["collection"]["storage_ok"] is True


def test_collect_backups_unexpected_exception_is_null_and_isolated():
    c = make_collector(proxmox_mock=_one_node_mock())
    with patch.object(c, "_collect_backups", side_effect=RuntimeError("bug")):
        result = c.collect()
    assert result["backups"] is None
    assert result["collection"]["error"] is None
    assert result["version"] == "8"


def _ttl_mocks(clock):
    """Patch both the cache's clock and the collector's age clock."""
    return (
        patch.object(proxmox_module, "time", clock),
        patch("fivenines_agent.cache.time", clock),
    )


def test_collect_backups_cached_within_ttl_and_age_grows():
    """Rule 3: the second collect() inside the TTL performs zero content
    listings (and no backups node listing) while age_s grows; past the TTL
    the block is recomputed and age_s resets."""
    clock = _FakeClock()
    mock = _one_node_mock(
        storage_by_node={"pve1": [_dir_storage("local")]},
        content_by_node_storage={"pve1": {"local": [_volume(100, 1)]}},
    )
    p1, p2 = _ttl_mocks(clock)
    with p1, p2:
        first = make_collector(proxmox_mock=mock).collect()
        assert first["backups"]["age_s"] == 0
        assert len(mock._content_calls) == 1
        node_listings = mock.nodes.get.call_count

        clock.t += 30
        second = make_collector(proxmox_mock=mock).collect()
        assert len(mock._content_calls) == 1
        assert mock.nodes.get.call_count == node_listings + 4  # the flagged sections only
        assert second["backups"]["age_s"] == 30
        assert second["backups"]["guest_backups"] == first["backups"]["guest_backups"]

        clock.t += proxmox_module.BACKUPS_CACHE_TTL
        third = make_collector(proxmox_mock=mock).collect()
        assert len(mock._content_calls) == 2
        assert third["backups"]["age_s"] == 0


def test_collect_backups_emitted_block_is_a_copy_of_the_cached_one():
    """Mutating an emitted block (e.g. by a serializer) must not leak into
    the next tick's emission."""
    mock = _one_node_mock()
    first = make_collector(proxmox_mock=mock).collect()
    first["backups"]["tasks"].append("mutated")
    first["backups"]["age_s"] = 99
    second = make_collector(proxmox_mock=mock).collect()
    assert second["backups"]["age_s"] == 0
    # arrays are shared by reference (shallow copy): document, don't hide it
    assert second["backups"]["tasks"] == ["mutated"]


def test_collect_backups_failed_build_is_not_cached():
    """store_if: a None build is retried next tick, so a recovered API is
    reported promptly instead of serving the failure for the rest of the TTL."""
    c = make_collector(proxmox_mock=_one_node_mock())
    block = (0.0, {"guest_backups": [], "tasks": [], "jobs": [], "not_backed_up": [], "errors": []})
    with patch.object(c, "_build_backups_block", side_effect=[None, block]) as build:
        assert c._collect_backups() is None
        assert c._collect_backups()["guest_backups"] == []
        assert build.call_count == 2
    # ...and the good block IS cached afterwards
    with patch.object(c, "_build_backups_block") as build:
        assert c._collect_backups()["tasks"] == []
        build.assert_not_called()


def test_collect_backups_cache_keyed_on_connection_identity():
    a = _one_node_mock(storage_by_node={"pve1": [_dir_storage("local")]})
    b = _one_node_mock(storage_by_node={"pve1": [_dir_storage("local")]})
    make_collector(proxmox_mock=a, host="pve-a").collect()
    make_collector(proxmox_mock=b, host="pve-b").collect()
    assert len(a._content_calls) == 1 and len(b._content_calls) == 1
    assert make_collector(proxmox_mock=a, host="pve-a")._backups_cache_key == (
        "pve-a",
        8006,
        "root@pam!claude",
        True,
    )


def test_collect_backups_age_never_negative():
    clock = _FakeClock(t=1000.0)
    c = make_collector(proxmox_mock=_one_node_mock())
    p1, p2 = _ttl_mocks(clock)
    with p1, p2:
        block = {"guest_backups": [], "tasks": [], "jobs": [], "not_backed_up": [], "errors": []}
        proxmox_module._backups_cache._entries[c._backups_cache_key] = (
            clock.t,
            (clock.t + 100, block),
            proxmox_module.BACKUPS_CACHE_TTL,
        )
        assert c._collect_backups()["age_s"] == 0


def test_no_new_config_key_for_backups():
    """Rule 4: config['proxmox'] is splatted into proxmox_metrics(**config);
    the TTL and caps are constants, never parameters."""
    import inspect

    params = set(inspect.signature(proxmox_metrics).parameters)
    assert params == {"host", "port", "token_id", "token_secret", "verify_ssl"}
    for name in ("BACKUPS_CACHE_TTL", "MAX_GUEST_BACKUPS", "MAX_TASKS_PER_NODE", "MAX_BACKUP_JOBS", "MAX_NOT_BACKED_UP"):
        assert isinstance(getattr(proxmox_module, name), int)


# --- audit additions (#156 ship review) --------------------------------------


def test_proxmox_metrics_outer_except_requires_truthy_proxmoxapi():
    """T84 [REGRESSION]: proxmox_metrics' outer except is only REACHABLE when
    ProxmoxAPI is truthy. proxmoxer is an optional import and is absent from
    the test venv, so T2 -- which patches ProxmoxCollector but not ProxmoxAPI
    -- returns at the `ProxmoxAPI is None` guard and never runs the handler it
    names (the 3 permanently-uncovered lines). Patch both."""
    with patch("fivenines_agent.proxmox.ProxmoxAPI", MagicMock()), patch(
        "fivenines_agent.proxmox.ProxmoxCollector",
        side_effect=RuntimeError("ctor fail"),
    ):
        assert proxmox_metrics(token_id="root@pam!c", token_secret="s") is None


def test_proxmox_metrics_collect_raising_is_swallowed():
    """T85: collect() raising (not just the ctor) is caught by the same outer
    except -- proxmox_metrics never propagates into the collection loop."""
    collector = MagicMock()
    collector.collect.side_effect = RuntimeError("collect boom")
    with patch("fivenines_agent.proxmox.ProxmoxAPI", MagicMock()), patch(
        "fivenines_agent.proxmox.ProxmoxCollector", return_value=collector
    ):
        assert proxmox_metrics(token_id="root@pam!c", token_secret="s") is None


def test_backup_error_redacts_secrets_in_api_messages():
    """T86: _backup_error puts the API's OWN reason on the wire, so it routes
    that reason through logs.redact(). A PVE auth failure can quote credential
    material into its message; without redact it would reach the backend
    verbatim inside backups.errors[].message."""
    errors = []
    proxmox_module._backup_error(
        errors,
        "storage",
        "500 auth failed: password=hunter2seekrit",
        node="pve1",
        storage="pbs",
    )
    assert "hunter2seekrit" not in errors[0]["message"]
    assert "[REDACTED]" in errors[0]["message"]
    assert errors[0]["node"] == "pve1" and errors[0]["storage"] == "pbs"


def test_collect_backups_partial_block_is_cached_within_ttl():
    """T87: the docstring contract that a PARTIAL block IS cached -- retrying
    a 403 every tick would not change it, and the per-storage error already
    tells the server what is missing. Only a None build is retried (T/2399).
    Without this, tightening store_if to reject blocks carrying errors would
    silently re-list the failing storage on every tick."""
    clock = _FakeClock()
    mock = _one_node_mock(
        storage_by_node={"pve1": [_dir_storage("local"), _dir_storage("pbs")]},
        content_by_node_storage={"pve1": {"local": [_volume(100, 1)]}},
        content_raises_for={"pve1/pbs"},
    )
    p1, p2 = _ttl_mocks(clock)
    with p1, p2:
        first = make_collector(proxmox_mock=mock).collect()
        assert [e["storage"] for e in first["backups"]["errors"]] == ["pbs"]
        calls = len(mock._content_calls)

        clock.t += 30
        second = make_collector(proxmox_mock=mock).collect()
        assert len(mock._content_calls) == calls
        assert second["backups"]["errors"] == first["backups"]["errors"]
        assert second["backups"]["age_s"] == 30


def test_guest_backups_non_dict_verification_is_omitted():
    """T88: PBS spells `verification` as an object. A daemon (or a future
    version) reporting it as a bare string must omit the key rather than ship
    {'state': None, 'upid': None}, which the server would read as a real
    verification record with an unknown state."""
    mock = _one_node_mock(
        storage_by_node={"pve1": [_dir_storage("local")]},
        content_by_node_storage={
            "pve1": {"local": [_volume(100, 10, verification="ok")]}
        },
    )
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(["pve1"], [])
    assert entries[0]["latest_ctime"] == 10
    assert "verification" not in entries[0]


def test_holds_backups_non_string_content_lists_anyway():
    """T89: `content` only EXCLUDES a storage when it is the comma-separated
    string PVE documents. Any other shape falls through to 'list it and find
    out' -- dropping it instead would make the storage's guests read as never
    backed up, with no error naming the storage."""
    holds = proxmox_module._holds_backups
    assert holds({"content": ["backup"]}) is True
    assert holds({"content": None}) is True
    assert holds({"content": ["images", "rootdir"]}) is True
    assert holds({"content": "backup,images", "enabled": "0"}) is False


def test_as_int_overflow_returns_none():
    """T90: the OverflowError arm of _as_int -- inf is what a JSON float
    overflow decodes to, and int(inf) raises OverflowError, not ValueError."""
    as_int = proxmox_module._as_int
    assert as_int(float("inf")) is None
    assert as_int(float("-inf")) is None


def test_guest_backups_one_guest_on_two_storages_is_two_entries():
    """T91: entries key on (vmid, storage, node), so a guest backed up to two
    targets gets one entry per target -- the shape the server needs to answer
    'backed up somewhere in the last N hours, whatever the target'. Sorted by
    (vmid, storage, node)."""
    mock = _one_node_mock(
        storage_by_node={"pve1": [_dir_storage("zzz"), _dir_storage("aaa")]},
        content_by_node_storage={
            "pve1": {"zzz": [_volume(100, 50)], "aaa": [_volume(100, 10)]}
        },
    )
    errors = []
    entries = make_collector(proxmox_mock=mock)._collect_guest_backups(["pve1"], errors)
    assert errors == []
    assert [(e["vmid"], e["storage"], e["latest_ctime"]) for e in entries] == [
        (100, "aaa", 10),
        (100, "zzz", 50),
    ]


def test_backups_deadline_skips_remaining_reads_and_names_each():
    """D2 (#156 ship review): the block runs under BACKUPS_COLLECT_DEADLINE.
    Here the very first content listing burns the whole budget; every read
    after it is SKIPPED (no API call) and recorded under its own scope, so
    the server reads those guests as unknown. The shared storage seen again
    on pve2 records no second error."""
    clock = _FakeClock()
    shared = {"storage": "pbs", "type": "pbs", "content": "backup", "shared": 1, "active": 1}
    mock = _one_node_mock(
        nodes=[{"node": "pve1"}, {"node": "pve2"}],
        storage_by_node={
            "pve1": [_dir_storage("local"), shared],
            "pve2": [shared, _dir_storage("local")],
        },
        content_by_node_storage={"pve1": {"local": [_volume(100, 1)]}},
        tasks_by_node={"pve1": [{"upid": "U"}]},
        backup_jobs=[{"id": "j"}],
        not_backed_up=[{"vmid": 1}],
    )
    nm = mock.nodes("pve1")
    inner = nm.storage.side_effect

    def slow_storage_call(name):
        sm = inner(name)
        real_get = sm.content.get.side_effect

        def slow_get(**params):
            clock.t += proxmox_module.BACKUPS_COLLECT_DEADLINE + 1
            return real_get(**params)

        sm.content.get.side_effect = slow_get
        return sm

    nm.storage.side_effect = slow_storage_call

    p1, p2 = _ttl_mocks(clock)
    with p1, p2:
        result = make_collector(proxmox_mock=mock).collect()

    backups = result["backups"]
    assert [e["vmid"] for e in backups["guest_backups"]] == [100]
    assert backups["tasks"] == [] and backups["jobs"] == [] and backups["not_backed_up"] == []
    msg = proxmox_module._DEADLINE_MESSAGE
    assert backups["errors"] == [
        {"scope": "storage", "node": "pve1", "storage": "pbs", "message": msg},
        {"scope": "storage", "node": "pve2", "storage": None, "message": msg},
        {"scope": "tasks", "node": "pve1", "storage": None, "message": msg},
        {"scope": "tasks", "node": "pve2", "storage": None, "message": msg},
        {"scope": "jobs", "node": None, "storage": None, "message": msg},
        {"scope": "not_backed_up", "node": None, "storage": None, "message": msg},
    ]
    assert len(mock._content_calls) == 1
    mock.nodes("pve1").tasks.get.assert_not_called()
    mock.cluster.backup.get.assert_not_called()
    # collection is untouched by a budget-trimmed block (rule 2)
    assert result["collection"]["error"] is None


def test_backups_deadline_skips_local_storage_and_is_cached():
    """A local storage hit by the budget is named (node + storage); the
    trimmed block is still cached, so the next tick within the TTL does not
    re-spend the budget."""
    clock = _FakeClock()
    mock = _one_node_mock(
        storage_by_node={"pve1": [_dir_storage("a"), _dir_storage("b")]},
        content_by_node_storage={"pve1": {"a": [_volume(1, 1)], "b": [_volume(2, 1)]}},
    )
    nm = mock.nodes("pve1")
    inner = nm.storage.side_effect

    def slow_storage_call(name):
        sm = inner(name)
        real_get = sm.content.get.side_effect

        def slow_get(**params):
            clock.t += proxmox_module.BACKUPS_COLLECT_DEADLINE
            return real_get(**params)

        sm.content.get.side_effect = slow_get
        return sm

    nm.storage.side_effect = slow_storage_call
    p1, p2 = _ttl_mocks(clock)
    with p1, p2:
        first = make_collector(proxmox_mock=mock).collect()["backups"]
        second = make_collector(proxmox_mock=mock).collect()["backups"]
    assert [e["storage"] for e in first["guest_backups"]] == ["a"]
    assert first["errors"][0] == {
        "scope": "storage",
        "node": "pve1",
        "storage": "b",
        "message": proxmox_module._DEADLINE_MESSAGE,
    }
    assert len(mock._content_calls) == 1
    assert second["errors"] == first["errors"]


def test_deadline_hit_none_means_unbounded():
    errors = []
    assert proxmox_module._deadline_hit(None, errors, "jobs") is False
    assert proxmox_module._deadline_hit(float("inf"), errors, "jobs") is False
    assert proxmox_module._deadline_hit(0.0, errors, "jobs") is True
    assert errors == [
        {"scope": "jobs", "node": None, "storage": None, "message": proxmox_module._DEADLINE_MESSAGE}
    ]
