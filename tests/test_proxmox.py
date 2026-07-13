"""Tests for fivenines_agent.proxmox module."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from fivenines_agent.proxmox import ProxmoxCollector, _record_failure, proxmox_metrics


def make_proxmox_mock(
    version=None,
    cluster_status=None,
    cluster_status_raises=False,
    nodes=None,
    nodes_raises=False,
    node_status_by_name=None,
    node_status_raises_for=None,
    qemu_by_node=None,
    qemu_raises_for=None,
    lxc_by_node=None,
    lxc_raises_for=None,
    storage_by_node=None,
    storage_raises_for=None,
    version_raises=False,
):
    """Build a MagicMock simulating proxmoxer.ProxmoxAPI chained-call API.

    Each kwarg controls one endpoint. The `_raises_for` variants take a set
    of node names that should raise instead of returning data.
    """
    mock = MagicMock()

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
    elif nodes is not None:
        mock.nodes.get.return_value = nodes

    node_status_raises_for = node_status_raises_for or set()
    qemu_raises_for = qemu_raises_for or set()
    lxc_raises_for = lxc_raises_for or set()
    storage_raises_for = storage_raises_for or set()

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


def test_collect_returns_dict_with_seven_keys():
    """T14: collect returns dict with all seven top-level keys (six data keys
    plus the 1.10.0 'collection' flags block)."""
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
_PAYLOAD_KEYS = {"version", "cluster", "nodes", "vms", "lxc", "storage", "collection"}
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
        assert set(storage) == _STORAGE_KEYS


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
