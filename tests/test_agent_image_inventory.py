"""Tests for the Agent wiring of Docker image OS-package inventory: deriving the
image->container map from the collected docker payload, the enqueue gate, the
configured-socket_url push into the permission probe, and cleanup teardown.
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock libvirt before any fivenines_agent imports that transitively need it.
sys.modules.setdefault("libvirt", MagicMock())

import fivenines_agent.agent as agent_module  # noqa: E402
from fivenines_agent.agent import Agent  # noqa: E402
from fivenines_agent.docker_image_inventory import (  # noqa: E402
    ImageInventoryCoordinator,
)
from fivenines_agent.synchronization_queue import SynchronizationQueue  # noqa: E402

# --- _image_container_map ---


def _bare_agent():
    return Agent.__new__(Agent)


def test_image_map_from_docker_payload_dedupes_by_image():
    agent = _bare_agent()
    data = {
        "docker": {
            "containers": {
                "c1": {"image_id": "sha256:a"},
                "c2": {"image_id": "sha256:b"},
                "c3": {"image_id": "sha256:a"},  # same image -> first wins
            }
        }
    }
    assert agent._image_container_map(data) == {
        "sha256:a": "c1",
        "sha256:b": "c2",
    }


def test_image_map_skips_entries_without_image_id():
    agent = _bare_agent()
    data = {"docker": {"containers": {"c1": {"name": "x"}, "c2": {"image_id": None}}}}
    assert agent._image_container_map(data) == {}


def test_image_map_empty_when_docker_none_or_absent():
    agent = _bare_agent()
    assert agent._image_container_map({"docker": None}) == {}
    assert agent._image_container_map({}) == {}


_DOCKER_CONTRACT_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "docker_contract_payload.json"
)
with open(_DOCKER_CONTRACT_PATH) as _f:
    _DOCKER_SCENARIOS = json.load(_f)["scenarios"]


@pytest.mark.parametrize(
    "name",
    sorted(
        n
        for n, s in _DOCKER_SCENARIOS.items()
        if s["payload"] and s["payload"]["containers"]
    ),
)
def test_image_map_reads_the_key_docker_metrics_actually_emits(name):
    """Cross-module join: _image_container_map consumes data["docker"] produced
    by docker_metrics, so it must read the key that collector really emits. The
    docker contract fixture IS the byte-exact docker_metrics output (see
    test_docker.py), so driving the map off it locks the join -- otherwise a
    rename of image_id in docker.py would silently disable image inventory
    fleet-wide while every hand-written test kept passing."""
    payload = _DOCKER_SCENARIOS[name]["payload"]
    agent = _bare_agent()
    image_map = agent._image_container_map({"docker": payload})

    containers = payload["containers"]
    assert image_map, "no image digest derived from a real docker_metrics payload"
    for image_id, container_id in image_map.items():
        assert image_id.startswith("sha256:")
        assert containers[container_id]["image_id"] == image_id
    # Every container with a digest is represented by exactly one reader.
    assert set(image_map) == {
        e["image_id"] for e in containers.values() if e.get("image_id")
    }


# --- _handle_image_inventory ---


def _inventory_agent(tmp_path, config, uploader=None):
    agent = _bare_agent()
    agent.config = config
    agent.image_inventory_uploader = uploader
    agent.image_inventory_queue = SynchronizationQueue(maxsize=10)
    agent.image_inventory_coordinator = ImageInventoryCoordinator(
        str(tmp_path / "done")
    )
    return agent


_DATA = {"docker": {"containers": {"c1": {"image_id": "sha256:a"}}}}


def test_handle_inventory_noop_when_uploader_disabled(tmp_path):
    agent = _inventory_agent(tmp_path, {"image_inventory": True}, uploader=None)
    agent._handle_image_inventory(_DATA)
    assert agent.image_inventory_queue.qsize() == 0


def test_handle_inventory_noop_when_feature_off(tmp_path):
    agent = _inventory_agent(tmp_path, {"docker": True}, uploader=MagicMock())
    agent._handle_image_inventory(_DATA)
    assert agent.image_inventory_queue.qsize() == 0


def test_handle_inventory_noop_when_no_images(tmp_path):
    agent = _inventory_agent(tmp_path, {"image_inventory": True}, uploader=MagicMock())
    agent._handle_image_inventory({"docker": None})
    assert agent.image_inventory_queue.qsize() == 0


def test_handle_inventory_enqueues_with_socket_url_from_docker_config(tmp_path):
    agent = _inventory_agent(
        tmp_path,
        {"image_inventory": True, "docker": {"socket_url": "unix:///run/d.sock"}},
        uploader=MagicMock(),
    )
    agent._handle_image_inventory(_DATA)
    assert agent.image_inventory_queue.qsize() == 1
    job = agent.image_inventory_queue.get_nowait()
    assert job == {
        "image_id": "sha256:a",
        "container_id": "c1",
        "socket_url": "unix:///run/d.sock",
    }


def test_handle_inventory_socket_url_none_when_docker_not_dict(tmp_path):
    agent = _inventory_agent(
        tmp_path,
        {"image_inventory": True, "docker": True},
        uploader=MagicMock(),
    )
    agent._handle_image_inventory(_DATA)
    job = agent.image_inventory_queue.get_nowait()
    assert job["socket_url"] is None


# --- config["rescan_images"]: server-driven re-inventory (server issue #676) ---


def test_handle_inventory_honours_rescan_images(tmp_path):
    """End-to-end through the Agent hook: a digest already marked done is
    re-enqueued on the SAME tick the server asks for it, not the next one."""
    agent = _inventory_agent(
        tmp_path,
        {"image_inventory": True, "rescan_images": ["sha256:a"]},
        uploader=MagicMock(),
    )
    agent.image_inventory_coordinator.mark_done("sha256:a")

    agent._handle_image_inventory(_DATA)

    assert agent.image_inventory_queue.qsize() == 1
    assert agent.image_inventory_queue.get_nowait()["image_id"] == "sha256:a"


def test_handle_inventory_without_rescan_leaves_a_done_digest_alone(tmp_path):
    """The mirror image: without the directive a done digest stays done. This is
    what makes the test above prove the directive, not the selection path."""
    agent = _inventory_agent(
        tmp_path, {"image_inventory": True}, uploader=MagicMock()
    )
    agent.image_inventory_coordinator.mark_done("sha256:a")

    agent._handle_image_inventory(_DATA)

    assert agent.image_inventory_queue.qsize() == 0


def test_handle_inventory_rescan_runs_before_the_feature_gate_is_passed(tmp_path):
    """The directive must not be honoured when image inventory is off -- the
    server should never mutate agent state the operator disabled."""
    agent = _inventory_agent(
        tmp_path,
        {"rescan_images": ["sha256:a"]},
        uploader=MagicMock(),
    )
    agent.image_inventory_coordinator.mark_done("sha256:a")

    agent._handle_image_inventory(_DATA)

    assert agent.image_inventory_queue.qsize() == 0
    # still done: the disabled feature left the coordinator untouched
    assert agent.image_inventory_coordinator.select_jobs({"sha256:a": "c1"}, None) == []


# --- _apply_config_driven_refresh pushes the configured socket_url ---


def _refresh_agent():
    agent = _bare_agent()
    agent.permissions = MagicMock()
    agent.permissions.get_all.return_value = {}
    agent.permissions.get_reasons.return_value = {}
    agent.permissions.refresh_due.return_value = False
    agent._last_recheck_token = agent_module._RECHECK_UNSET
    agent.static_data = {}
    return agent


def test_apply_pushes_configured_socket_url_dict_branch():
    agent = _refresh_agent()
    agent._apply_config_driven_refresh(
        {"interval": 60, "docker": {"socket_url": "unix:///run/user/1000/docker.sock"}}
    )
    agent.permissions.set_docker_socket_url.assert_called_once_with(
        "unix:///run/user/1000/docker.sock"
    )


def test_apply_pushes_none_when_docker_config_not_dict():
    agent = _refresh_agent()
    agent._apply_config_driven_refresh({"interval": 60, "docker": True})
    agent.permissions.set_docker_socket_url.assert_called_once_with(None)


def test_socket_url_is_pushed_before_a_forced_reprobe():
    """Ordering invariant: the push must land BEFORE the recheck-token
    force_refresh, or the very re-detect the operator asked for still probes the
    stale socket and reports docker unavailable for another full interval."""
    agent = _refresh_agent()
    agent._last_recheck_token = "old"
    agent._apply_config_driven_refresh(
        {
            "interval": 60,
            "permissions_recheck_token": "new",
            "docker": {"socket_url": "unix:///run/user/1000/docker.sock"},
        }
    )
    called = [c[0] for c in agent.permissions.mock_calls]
    assert "force_refresh" in called
    assert called.index("set_docker_socket_url") < called.index("force_refresh")


# --- _cleanup tears down the image inventory uploader ---


def test_cleanup_stops_image_inventory_uploader(tmp_path):
    agent = _bare_agent()
    agent.queue = MagicMock()
    agent.synchronizer = None
    agent.log_uploader = None
    agent.image_inventory_uploader = MagicMock()
    agent.image_inventory_queue = MagicMock()

    with patch("fivenines_agent.agent.shutdown_mqtt"), pytest.raises(
        SystemExit
    ) as exc_info:
        agent._cleanup()

    assert exc_info.value.code == 0
    agent.image_inventory_uploader.stop.assert_called_once()
    agent.image_inventory_queue.put.assert_called_once_with(None)
    agent.image_inventory_uploader.join.assert_called_once()


# --- __init__ builds the inventory channel ---


def _construct_agent(tmp_path, synchronizer):
    """Run the real Agent.__init__ with only its host-dependent edges patched
    (signals, probe, banner, config dir, machine id, user context, synchronizer)
    so the image-inventory wiring it builds is exercised, not re-implemented in
    the test."""
    (tmp_path / "TOKEN").write_text("token\n")
    perms = MagicMock()
    perms.get_all.return_value = {}
    perms.get_reasons.return_value = {}
    with patch("fivenines_agent.agent.setup_signals"), patch(
        "fivenines_agent.agent.get_permissions", return_value=perms
    ), patch("fivenines_agent.agent.print_capabilities_banner"), patch(
        "fivenines_agent.agent.CONFIG_DIR", str(tmp_path)
    ), patch(
        "fivenines_agent.agent.dry_run", return_value=synchronizer is None
    ), patch(
        "fivenines_agent.agent.Synchronizer", return_value=synchronizer
    ), patch(
        "fivenines_agent.agent.get_user_context", return_value={}
    ), patch(
        "fivenines_agent.agent.get_machine_id", return_value="machine"
    ):
        return Agent()


def _teardown(agent):
    for uploader, queue in (
        (agent.image_inventory_uploader, agent.image_inventory_queue),
        (agent.log_uploader, agent.log_queue),
    ):
        if uploader is not None:
            uploader.stop()
            queue.put(None)
            uploader.join(timeout=2)
            assert not uploader.is_alive()


def test_init_wires_uploader_to_the_coordinator_and_synchronizer(tmp_path):
    """The callbacks are the retry loop: on_success=mark_done retires an
    immutable digest forever, on_failure=mark_failed releases it. Swapping them
    would either re-extract every image on every tick or never retry a transient
    failure -- and __init__ is the only place they are bound."""
    sync = MagicMock()
    agent = _construct_agent(tmp_path, sync)
    try:
        uploader = agent.image_inventory_uploader
        coordinator = agent.image_inventory_coordinator
        assert uploader is not None
        assert uploader.is_alive()
        assert uploader.build_fn is agent_module.build_image_inventory
        assert uploader.send_fn is sync.send_image_packages
        assert uploader._on_success == coordinator.mark_done
        assert uploader._on_failure == coordinator.mark_failed
        assert uploader.queue is agent.image_inventory_queue
        # done digests persist next to the other agent state, under CONFIG_DIR.
        assert coordinator.state_path == os.path.join(
            str(tmp_path), "image_inventory_done"
        )
    finally:
        _teardown(agent)


def test_init_skips_the_uploader_in_dry_run(tmp_path):
    """No synchronizer (--dry-run) -> no uploader thread, but the coordinator and
    queue still exist so _handle_image_inventory can no-op safely."""
    agent = _construct_agent(tmp_path, None)
    try:
        assert agent.synchronizer is None
        assert agent.image_inventory_uploader is None
        assert agent.image_inventory_coordinator is not None
        assert agent.image_inventory_queue.qsize() == 0
        agent._handle_image_inventory(_DATA)  # must not raise or enqueue
        assert agent.image_inventory_queue.qsize() == 0
    finally:
        _teardown(agent)
