"""Tests for the Docker container-state + metrics collector."""

import json
import os
from unittest.mock import MagicMock, patch

import docker as docker_lib
import pytest

import fivenines_agent.docker as docker_mod
from fivenines_agent.docker import (
    _block_io,
    _clean_name,
    _cpu_usage_percent,
    _health,
    _image_metadata,
    _normalize_timestamp,
    calculate_cpu_percent,
    calculate_memory_percent,
    calculate_memory_usage,
    docker_containers,
    docker_metrics,
    get_docker_client,
)

# ---------------------------------------------------------------------------
# Isolation: the warm-up cache and cap-log guard are module globals.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_docker_state():
    docker_mod.previous_stats.clear()
    docker_mod._cap_logged = False
    yield
    docker_mod.previous_stats.clear()
    docker_mod._cap_logged = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_OMIT = object()


def _attrs(
    name="/web-1",
    image_id="sha256:img",
    config_image="nginx:1.27",
    status="running",
    exit_code=0,
    oom=False,
    restart_count=0,
    started="2026-01-01T00:00:00Z",
    finished="0001-01-01T00:00:00Z",
    health=_OMIT,
):
    """Build a full-inspect attrs dict (what container.attrs is after reload)."""
    state = {
        "Status": status,
        "ExitCode": exit_code,
        "OOMKilled": oom,
        "StartedAt": started,
        "FinishedAt": finished,
    }
    if health is not _OMIT:
        state["Health"] = {"Status": health}
    return {
        "Name": name,
        "Image": image_id,
        "RestartCount": restart_count,
        "Config": {"Image": config_image},
        "State": state,
    }


def _stats(
    total=2000,
    kernel=500,
    user=1500,
    system=10000,
    online=4,
    throttle=None,
    usage=500,
    limit=1000,
    mem_stats=None,
    blkio=_OMIT,
    pids=None,
    networks=None,
):
    """Build a realistic container.stats() dict."""
    s = {
        "cpu_stats": {
            "cpu_usage": {
                "total_usage": total,
                "usage_in_kernelmode": kernel,
                "usage_in_usermode": user,
            },
            "system_cpu_usage": system,
            "online_cpus": online,
            "throttling_data": throttle
            or {"periods": 0, "throttled_periods": 0, "throttled_time": 0},
        },
        "memory_stats": {"usage": usage, "limit": limit, "stats": mem_stats or {}},
        "pids_stats": pids or {"current": 10, "limit": 4096},
    }
    if blkio is not _OMIT:
        s["blkio_stats"] = blkio
    if networks is not None:
        s["networks"] = networks
    return s


def _prev_stats(total=1000, kernel=100, user=400, system=5000):
    """A prior CPU sample (only cpu_stats is read from the previous sample)."""
    return {
        "cpu_stats": {
            "cpu_usage": {
                "total_usage": total,
                "usage_in_kernelmode": kernel,
                "usage_in_usermode": user,
            },
            "system_cpu_usage": system,
        }
    }


def _make_container(cid, full_attrs, sparse_attrs=None, stats=None, reload_error=None):
    """Mock a docker-py Container.

    Before reload(), attrs is the sparse listing; reload() swaps in the full
    inspect (matching real docker-py). Set reload_error to make reload() raise.
    """
    c = MagicMock()
    c.id = cid
    c.attrs = sparse_attrs if sparse_attrs is not None else {"Id": cid}

    if reload_error is not None:
        c.reload.side_effect = reload_error
    else:

        def _reload(_c=c, _full=full_attrs):
            _c.attrs = _full

        c.reload.side_effect = _reload

    if stats is None:
        c.stats.side_effect = AssertionError("stats() must not be called")
    else:
        c.stats.return_value = stats
    return c


def _make_image(tags=None, repo_digests=None):
    img = MagicMock()
    img.tags = tags if tags is not None else []
    img.attrs = {"RepoDigests": repo_digests if repo_digests is not None else []}
    return img


def _make_client(containers, images=None, list_error=None):
    images = images or {}
    client = MagicMock()
    if list_error is not None:
        client.containers.list.side_effect = list_error
    else:
        client.containers.list.return_value = containers

    def _images_get(image_id):
        if image_id in images:
            return images[image_id]
        raise docker_lib.errors.NotFound(f"no such image: {image_id}")

    client.images.get.side_effect = _images_get
    return client


# ===========================================================================
# get_docker_client
# ===========================================================================


class TestGetDockerClient:
    @patch("fivenines_agent.docker.docker")
    def test_from_env(self, mock_docker):
        client = MagicMock()
        mock_docker.from_env.return_value = client
        assert get_docker_client() is client
        mock_docker.from_env.assert_called_once()

    @patch("fivenines_agent.docker.docker")
    def test_with_socket_url(self, mock_docker):
        client = MagicMock()
        mock_docker.DockerClient.return_value = client
        assert get_docker_client(socket_url="unix:///var/run/docker.sock") is client
        mock_docker.DockerClient.assert_called_once_with(
            base_url="unix:///var/run/docker.sock"
        )

    @patch("fivenines_agent.docker.docker")
    def test_connection_error(self, mock_docker):
        mock_docker.errors.DockerException = docker_lib.errors.DockerException
        mock_docker.from_env.side_effect = docker_lib.errors.DockerException("nope")
        assert get_docker_client() is None


# ===========================================================================
# Small state helpers
# ===========================================================================


class TestCleanName:
    def test_strips_leading_slash(self):
        assert _clean_name("/web-1") == "web-1"

    def test_none(self):
        assert _clean_name(None) is None

    def test_empty(self):
        assert _clean_name("") is None


class TestNormalizeTimestamp:
    def test_passthrough_verbatim(self):
        assert (
            _normalize_timestamp("2026-07-15T09:12:33.123456789Z")
            == "2026-07-15T09:12:33.123456789Z"
        )

    def test_go_zero_value_becomes_null(self):
        assert _normalize_timestamp("0001-01-01T00:00:00Z") is None

    def test_none_and_empty(self):
        assert _normalize_timestamp(None) is None
        assert _normalize_timestamp("") is None


class TestHealth:
    def test_no_healthcheck_is_null(self):
        assert _health({"Status": "running"}) is None

    def test_healthy(self):
        assert _health({"Health": {"Status": "healthy"}}) == "healthy"

    def test_unhealthy(self):
        assert _health({"Health": {"Status": "unhealthy"}}) == "unhealthy"

    def test_non_dict_health_is_null(self):
        assert _health({"Health": "weird"}) is None


# ===========================================================================
# _block_io
# ===========================================================================


class TestBlockIo:
    def test_cgroup_v2_lowercase(self):
        stats = _stats(
            blkio={
                "io_service_bytes_recursive": [
                    {"op": "read", "value": 100},
                    {"op": "write", "value": 200},
                ]
            }
        )
        assert _block_io(stats) == (100, 200)

    def test_cgroup_v1_capitalized(self):
        stats = _stats(
            blkio={
                "io_service_bytes_recursive": [
                    {"op": "Read", "value": 10},
                    {"op": "Write", "value": 20},
                ]
            }
        )
        assert _block_io(stats) == (10, 20)

    def test_sums_multiple_entries_per_op(self):
        stats = _stats(
            blkio={
                "io_service_bytes_recursive": [
                    {"op": "read", "value": 100},
                    {"op": "write", "value": 900},
                    {"op": "read", "value": 23},
                    {"op": "write", "value": 54},
                ]
            }
        )
        assert _block_io(stats) == (123, 954)

    def test_ignores_other_ops_and_null_values(self):
        stats = _stats(
            blkio={
                "io_service_bytes_recursive": [
                    {"op": "read", "value": 5},
                    {"op": "sync", "value": 999},
                    {"op": "write", "value": None},
                ]
            }
        )
        assert _block_io(stats) == (5, 0)

    def test_missing_blkio_key_is_none(self):
        assert _block_io(_stats()) is None

    def test_none_list_is_none(self):
        assert _block_io(_stats(blkio={"io_service_bytes_recursive": None})) is None

    def test_empty_list_is_none(self):
        assert _block_io(_stats(blkio={"io_service_bytes_recursive": []})) is None


# ===========================================================================
# _image_metadata / image cache
# ===========================================================================


class TestImageMetadata:
    def test_reads_config_image_and_fetches_tags(self):
        client = MagicMock()
        client.images.get.return_value = _make_image(
            tags=["nginx:1.27", "nginx:latest"],
            repo_digests=["nginx@sha256:abc"],
        )
        cache = {}
        result = _image_metadata(
            {"Image": "sha256:id"}, {"Image": "nginx:1.27"}, client, cache
        )
        assert result == {
            "image": "nginx:1.27",
            "image_id": "sha256:id",
            "image_tags": ["nginx:1.27", "nginx:latest"],
            "image_repo_digests": ["nginx@sha256:abc"],
        }

    def test_image_falls_back_to_image_id_when_no_config_image(self):
        client = MagicMock()
        client.images.get.return_value = _make_image(tags=[])
        result = _image_metadata({"Image": "sha256:id"}, {}, client, {})
        assert result["image"] == "sha256:id"
        assert result["image_tags"] == []

    def test_image_fetch_failure_yields_empty_lists(self):
        client = MagicMock()
        client.images.get.side_effect = docker_lib.errors.NotFound("gone")
        result = _image_metadata(
            {"Image": "sha256:id"}, {"Image": "nginx:1.27"}, client, {}
        )
        assert result["image"] == "nginx:1.27"
        assert result["image_id"] == "sha256:id"
        assert result["image_tags"] == []
        assert result["image_repo_digests"] == []

    def test_cache_is_used_across_containers_sharing_an_image(self):
        client = MagicMock()
        client.images.get.return_value = _make_image(tags=["shared:1"])
        cache = {}
        _image_metadata(
            {"Image": "sha256:shared"}, {"Image": "shared:1"}, client, cache
        )
        _image_metadata(
            {"Image": "sha256:shared"}, {"Image": "shared:1"}, client, cache
        )
        assert client.images.get.call_count == 1


# ===========================================================================
# docker_containers -- state block, all statuses, warm-up
# ===========================================================================


class TestDockerContainersStateBlock:
    def _run(self, containers, images=None, seed=None):
        client = _make_client(containers, images or {})
        with patch(
            "fivenines_agent.docker.get_docker_client", return_value=client
        ), patch(
            "fivenines_agent.docker.previous_stats", seed if seed is not None else {}
        ):
            return docker_containers()

    def test_lists_all_containers_sparse(self):
        client = _make_client([])
        with patch("fivenines_agent.docker.get_docker_client", return_value=client):
            docker_containers()
        client.containers.list.assert_called_once_with(all=True, sparse=True)

    def test_exited_container_ships_state_only(self):
        c = _make_container(
            "e1",
            _attrs(
                name="/job",
                status="exited",
                exit_code=137,
                oom=True,
                finished="2026-07-15T08:05:00Z",
            ),
        )
        result = self._run([c], {"sha256:img": _make_image(tags=["busybox:latest"])})
        entry = result["e1"]
        assert entry["status"] == "exited"
        assert entry["exit_code"] == 137
        assert entry["oom_killed"] is True
        assert entry["finished_at"] == "2026-07-15T08:05:00Z"
        assert entry["health"] is None
        # No stats keys at all.
        assert "cpu_percent" not in entry
        assert "memory_usage" not in entry
        assert "block_read_bytes" not in entry

    def test_created_container_has_null_timestamps(self):
        c = _make_container(
            "c1",
            _attrs(
                status="created",
                started="0001-01-01T00:00:00Z",
                finished="0001-01-01T00:00:00Z",
            ),
        )
        entry = self._run([c], {"sha256:img": _make_image()})["c1"]
        assert entry["status"] == "created"
        assert entry["started_at"] is None
        assert entry["finished_at"] is None

    def test_status_passed_through_verbatim(self):
        for status in ("paused", "restarting", "removing", "dead"):
            c = _make_container(f"x-{status}", _attrs(status=status))
            entry = self._run([c], {"sha256:img": _make_image()})[f"x-{status}"]
            assert entry["status"] == status
            assert "cpu_percent" not in entry

    def test_running_first_sighting_is_state_only(self):
        c = _make_container(
            "r1", _attrs(status="running", health="starting"), stats=_stats()
        )
        seed = {}
        client = _make_client([c], {"sha256:img": _make_image(tags=["a:1"])})
        with patch(
            "fivenines_agent.docker.get_docker_client", return_value=client
        ), patch("fivenines_agent.docker.previous_stats", seed):
            entry = docker_containers()["r1"]
        assert entry["status"] == "running"
        assert entry["health"] == "starting"
        assert "cpu_percent" not in entry
        # The sample is still recorded (in the patched cache) for the next tick.
        assert "r1" in seed

    def test_running_second_tick_has_full_stats(self):
        c = _make_container(
            "r2",
            _attrs(status="running", health="healthy"),
            stats=_stats(
                total=2000,
                system=10000,
                kernel=600,
                user=1400,
                usage=500,
                limit=1000,
                blkio={
                    "io_service_bytes_recursive": [
                        {"op": "read", "value": 111},
                        {"op": "write", "value": 222},
                    ]
                },
                networks={"eth0": {"rx_bytes": 1, "tx_bytes": 2}},
            ),
        )
        seed = {"r2": _prev_stats(total=1000, system=5000, kernel=100, user=400)}
        entry = self._run([c], {"sha256:img": _make_image(tags=["a:1"])}, seed=seed)[
            "r2"
        ]
        assert entry["cpu_percent"] == 20.0
        assert entry["memory_usage"] == 500
        assert entry["memory_limit"] == 1000
        assert entry["online_cpus"] == 4
        assert entry["block_read_bytes"] == 111
        assert entry["block_write_bytes"] == 222
        assert entry["networks"] == {"eth0": {"rx_bytes": 1, "tx_bytes": 2}}
        assert isinstance(entry["cpu_kernelmode_percent"], float)

    def test_running_without_blkio_omits_block_keys(self):
        c = _make_container("r3", _attrs(status="running"), stats=_stats())
        seed = {"r3": _prev_stats()}
        entry = self._run([c], {"sha256:img": _make_image()}, seed=seed)["r3"]
        assert "cpu_percent" in entry
        assert "block_read_bytes" not in entry
        assert "block_write_bytes" not in entry

    def test_running_without_networks_omits_networks_key(self):
        c = _make_container("r4", _attrs(status="running"), stats=_stats())
        seed = {"r4": _prev_stats()}
        entry = self._run([c], {"sha256:img": _make_image()}, seed=seed)["r4"]
        assert "networks" not in entry

    def test_zero_containers_is_empty_dict_not_none(self):
        assert self._run([]) == {}


# ===========================================================================
# docker_containers -- error isolation and failure signalling
# ===========================================================================


class TestDockerContainersErrors:
    def _run(
        self, containers, images=None, seed=None, list_error=None, client="__build__"
    ):
        if client == "__build__":
            client = _make_client(containers, images or {}, list_error=list_error)
        with patch(
            "fivenines_agent.docker.get_docker_client", return_value=client
        ), patch(
            "fivenines_agent.docker.previous_stats", seed if seed is not None else {}
        ):
            return docker_containers()

    def test_connect_failure_returns_none(self):
        assert self._run([], client=None) is None

    def test_list_failure_returns_none(self):
        assert self._run([], list_error=RuntimeError("boom")) is None

    def test_notfound_race_skips_only_that_container(self):
        gone = _make_container(
            "gone", _attrs(), reload_error=docker_lib.errors.NotFound("removed")
        )
        alive = _make_container("alive", _attrs(status="exited"))
        result = self._run([gone, alive], {"sha256:img": _make_image()})
        assert "gone" not in result
        assert "alive" in result

    def test_generic_exception_skips_only_that_container(self):
        bad = _make_container("bad", _attrs(), reload_error=RuntimeError("kaboom"))
        good = _make_container("good", _attrs(status="exited"))
        result = self._run([bad, good], {"sha256:img": _make_image()})
        assert "bad" not in result
        assert "good" in result

    def test_stats_failure_skips_only_that_container(self):
        broken = _make_container("broken", _attrs(status="running"))
        broken.stats.side_effect = RuntimeError("stats boom")
        ok = _make_container("ok", _attrs(status="exited"))
        result = self._run([broken, ok], {"sha256:img": _make_image()})
        assert "broken" not in result
        assert "ok" in result

    def test_image_metadata_failure_keeps_entry(self):
        # No image registered -> images.get raises NotFound inside the helper.
        c = _make_container("c1", _attrs(status="exited", config_image="myapp:v1"))
        result = self._run([c], images={})
        entry = result["c1"]
        assert entry["image"] == "myapp:v1"
        assert entry["image_tags"] == []
        assert entry["image_repo_digests"] == []


# ===========================================================================
# previous_stats pruning / warm-up lifecycle
# ===========================================================================


class TestPreviousStatsLifecycle:
    def _run(self, containers, seed, images=None):
        client = _make_client(containers, images or {"sha256:img": _make_image()})
        with patch(
            "fivenines_agent.docker.get_docker_client", return_value=client
        ), patch("fivenines_agent.docker.previous_stats", seed):
            docker_containers()
            return seed

    def test_vanished_container_is_pruned(self):
        c = _make_container("keep", _attrs(status="running"), stats=_stats())
        seed = {"keep": _prev_stats(), "vanished": _prev_stats()}
        after = self._run([c], seed)
        assert "vanished" not in after
        assert "keep" in after

    def test_restart_same_id_keeps_warmup(self):
        # Same id present with a prior sample -> stats ship this tick (warm-up
        # survived the restart) and the id stays in the cache.
        c = _make_container("same", _attrs(status="running"), stats=_stats(total=9999))
        seed = {"same": _prev_stats()}
        client = _make_client([c], {"sha256:img": _make_image()})
        with patch(
            "fivenines_agent.docker.get_docker_client", return_value=client
        ), patch("fivenines_agent.docker.previous_stats", seed):
            result = docker_containers()
        assert "cpu_percent" in result["same"]
        assert "same" in seed

    def test_recreate_new_id_restarts_warmup(self):
        # Old id vanished, new id first-sighted -> new entry is state-only and
        # old id's warm-up is pruned.
        new = _make_container("new-id", _attrs(status="running"), stats=_stats())
        seed = {"old-id": _prev_stats()}
        after = self._run([new], seed)
        assert "old-id" not in after
        assert "new-id" in after  # sample recorded, but...
        # ...the emitted entry had no stats (first sighting on the new id).


# ===========================================================================
# container cap
# ===========================================================================


class TestContainerCap:
    def _sparse(self, cid, state, created):
        return {"Id": cid, "State": state, "Created": created}

    def test_cap_prioritizes_running_and_logs_once(self):
        containers = []
        # One running container, deliberately the OLDEST by Created, so it would
        # be dropped if running were not prioritized.
        running = _make_container(
            "run-old",
            _attrs(status="running"),
            sparse_attrs=self._sparse("run-old", "running", 1),
            stats=_stats(),
        )
        containers.append(running)
        # 600 newer exited containers.
        for i in range(600):
            cid = f"ex-{i}"
            containers.append(
                _make_container(
                    cid,
                    _attrs(name=f"/{cid}", status="exited"),
                    sparse_attrs=self._sparse(cid, "exited", 1000 + i),
                )
            )

        client = _make_client(containers, {"sha256:img": _make_image()})
        with patch(
            "fivenines_agent.docker.get_docker_client", return_value=client
        ), patch("fivenines_agent.docker.previous_stats", {}), patch(
            "fivenines_agent.docker.log"
        ) as mock_log:
            result = docker_containers()
            # Second call: over-cap again, but must not log a second time.
            docker_containers()

        assert len(result) == docker_mod._MAX_CONTAINERS
        assert "run-old" in result  # running prioritized despite being oldest
        cap_logs = [
            call for call in mock_log.call_args_list if "exceeds cap" in call.args[0]
        ]
        assert len(cap_logs) == 1

    def test_under_cap_returns_all(self):
        containers = [
            _make_container(f"c{i}", _attrs(name=f"/c{i}", status="exited"))
            for i in range(3)
        ]
        client = _make_client(containers, {"sha256:img": _make_image()})
        with patch(
            "fivenines_agent.docker.get_docker_client", return_value=client
        ), patch("fivenines_agent.docker.previous_stats", {}):
            result = docker_containers()
        assert len(result) == 3


# ===========================================================================
# CPU / memory math (unchanged core)
# ===========================================================================


class TestCpuUsagePercent:
    def test_kernelmode(self):
        stats = _stats(kernel=600, system=10000)
        prev = _stats(kernel=100, system=5000)
        assert (
            _cpu_usage_percent(stats, prev, "usage_in_kernelmode")
            == (500 / 5000) * 100.0
        )

    def test_usermode(self):
        stats = _stats(user=1400, system=10000)
        prev = _stats(user=400, system=5000)
        assert (
            _cpu_usage_percent(stats, prev, "usage_in_usermode")
            == (1000 / 5000) * 100.0
        )

    def test_zero_system_delta(self):
        stats = _stats(kernel=600, system=5000)
        prev = _stats(kernel=100, system=5000)
        assert _cpu_usage_percent(stats, prev, "usage_in_kernelmode") == 0.0

    def test_zero_cpu_delta(self):
        stats = _stats(kernel=100, system=10000)
        prev = _stats(kernel=100, system=5000)
        assert _cpu_usage_percent(stats, prev, "usage_in_kernelmode") == 0.0

    def test_missing_key_returns_zero(self):
        stats = {"cpu_stats": {"cpu_usage": {}, "system_cpu_usage": 10000}}
        prev = {"cpu_stats": {"cpu_usage": {}, "system_cpu_usage": 5000}}
        assert _cpu_usage_percent(stats, prev, "usage_in_kernelmode") == 0.0


class TestCalculateCpuPercent:
    def test_normal(self):
        stats = _stats(total=2000, system=10000)
        prev = _stats(total=1000, system=5000)
        assert calculate_cpu_percent(stats, prev) == (1000 / 5000) * 100.0

    def test_zero_delta(self):
        stats = _stats(total=1000, system=5000)
        prev = _stats(total=1000, system=5000)
        assert calculate_cpu_percent(stats, prev) == 0.0


class TestCalculateMemoryPercent:
    def test_with_total_inactive_file(self):
        stats = _stats(usage=500, limit=1000, mem_stats={"total_inactive_file": 100})
        assert calculate_memory_percent(stats) == (400 / 1000) * 100.0

    def test_with_inactive_file(self):
        stats = _stats(usage=500, limit=1000, mem_stats={"inactive_file": 50})
        assert calculate_memory_percent(stats) == (450 / 1000) * 100.0

    def test_fallback(self):
        stats = _stats(usage=500, limit=1000)
        assert calculate_memory_percent(stats) == (500 / 1000) * 100.0


class TestCalculateMemoryUsage:
    def test_with_total_inactive_file(self):
        stats = _stats(usage=500, mem_stats={"total_inactive_file": 100})
        assert calculate_memory_usage(stats) == 400

    def test_with_inactive_file(self):
        stats = _stats(usage=500, mem_stats={"inactive_file": 50})
        assert calculate_memory_usage(stats) == 450

    def test_fallback(self):
        stats = _stats(usage=500)
        assert calculate_memory_usage(stats) == 500


# ===========================================================================
# docker_metrics wrapper
# ===========================================================================


class TestDockerMetrics:
    @patch("fivenines_agent.docker.docker_containers")
    def test_wraps_containers(self, mock_containers):
        mock_containers.return_value = {"c1": {"name": "web"}}
        result = docker_metrics(socket_url="unix:///custom.sock")
        mock_containers.assert_called_once_with("unix:///custom.sock")
        assert result == {"containers": {"c1": {"name": "web"}}}

    @patch("fivenines_agent.docker.docker_containers")
    def test_empty_is_wrapped_not_none(self, mock_containers):
        mock_containers.return_value = {}
        assert docker_metrics() == {"containers": {}}

    @patch("fivenines_agent.docker.docker_containers")
    def test_none_propagates_as_none(self, mock_containers):
        mock_containers.return_value = None
        assert docker_metrics() is None


# ===========================================================================
# Shared contract fixture (cross-repo, see docker_contract_payload.json)
# ===========================================================================
#
# For each scenario, docker_metrics() built from the mocked Docker SDK in
# scenario["sdk"] must equal scenario["payload"] byte-for-byte -- the exact
# value the server's DockerContainer ingester parses under data["docker"].
# The server posts each payload and asserts ingestion; change only in lockstep
# with the byte-identical copy in the server's spec/fixtures/.

_CONTRACT_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "docker_contract_payload.json"
)

with open(_CONTRACT_FIXTURE_PATH) as _f:
    _CONTRACT = json.load(_f)

_CONTRACT_SCENARIOS = _CONTRACT["scenarios"]

# The unconditional identity + state block: present on EVERY container entry.
_STATE_KEYS = {
    "name",
    "image",
    "image_id",
    "image_tags",
    "image_repo_digests",
    "status",
    "exit_code",
    "oom_killed",
    "restart_count",
    "started_at",
    "finished_at",
    "health",
}
# Stats keys, added only for a running container with a prior sample.
_STATS_KEYS = {
    "cpu_percent",
    "memory_percent",
    "memory_usage",
    "memory_limit",
    "pids_stats",
    "cpu_throttling",
    "online_cpus",
    "cpu_kernelmode_percent",
    "cpu_usermode_percent",
}
_OPTIONAL_STATS_KEYS = {"block_read_bytes", "block_write_bytes", "networks"}
_STATE_ONLY_SCENARIOS = {
    "running_first_sighting",
    "exited_oom",
    "exited_clean",
    "restart_looping",
    "paused",
    "created_never_started",
}


def _container_from_spec(spec):
    c = MagicMock()
    c.id = spec["id"]
    full = spec["attrs"]
    c.attrs = {"Id": spec["id"]}

    def _reload(_c=c, _full=full):
        _c.attrs = _full

    c.reload.side_effect = _reload
    if "stats" in spec:
        c.stats.return_value = spec["stats"]
    else:
        c.stats.side_effect = AssertionError(
            "stats() called on a non-running container"
        )
    return c


def _client_from_sdk(sdk):
    if sdk.get("connect_error"):
        return None
    containers = [_container_from_spec(c) for c in sdk.get("containers", [])]
    images = {
        iid: _make_image(tags=meta["tags"], repo_digests=meta["repo_digests"])
        for iid, meta in sdk.get("images", {}).items()
    }
    return _make_client(containers, images)


@pytest.mark.parametrize("scenario_name", sorted(_CONTRACT_SCENARIOS))
def test_contract_fixture_scenarios(scenario_name):
    """SHARED FIXTURE (cross-repo contract): each scenario's payload is exactly
    what docker_metrics() emits under data['docker'] for that Docker SDK state,
    with only the SDK mocked."""
    scenario = _CONTRACT_SCENARIOS[scenario_name]
    sdk = scenario["sdk"]
    seed = {
        c["id"]: c["previous_stats"]
        for c in sdk.get("containers", [])
        if "previous_stats" in c
    }
    client = _client_from_sdk(sdk)
    with patch("fivenines_agent.docker.get_docker_client", return_value=client), patch(
        "fivenines_agent.docker.previous_stats", seed
    ):
        out = docker_metrics()
    assert out == scenario["payload"]


@pytest.mark.parametrize("scenario_name", sorted(_CONTRACT_SCENARIOS))
def test_contract_state_block_always_present(scenario_name):
    """Every container entry carries the full state block; any extra keys are
    strictly stats keys. A renamed/dropped state field fails HERE."""
    payload = _CONTRACT_SCENARIOS[scenario_name]["payload"]
    if payload is None:
        return
    for entry in payload["containers"].values():
        assert _STATE_KEYS <= set(entry)
        extra = set(entry) - _STATE_KEYS
        assert extra <= _STATS_KEYS | _OPTIONAL_STATS_KEYS


def test_contract_state_only_scenarios_have_no_stats():
    """Non-running (and first-sighting running) entries are state-only."""
    for name in _STATE_ONLY_SCENARIOS:
        for entry in _CONTRACT_SCENARIOS[name]["payload"]["containers"].values():
            assert set(entry) == _STATE_KEYS


def test_contract_running_with_stats_has_full_stats_block():
    """Second-tick running entries carry the full stats key set."""
    for name in ("running_healthy", "running_no_healthcheck", "unhealthy"):
        for entry in _CONTRACT_SCENARIOS[name]["payload"]["containers"].values():
            assert _STATS_KEYS <= set(entry)


def test_contract_raw_blkio_stats_dropped():
    """The raw blkio_stats dict is never in the payload (replaced by the clean
    block_read_bytes / block_write_bytes counters)."""
    for scenario in _CONTRACT_SCENARIOS.values():
        payload = scenario["payload"]
        if payload is None:
            continue
        for entry in payload["containers"].values():
            assert "blkio_stats" not in entry


def test_contract_failure_signal_is_null_payload():
    """Only daemon_unreachable yields a null payload; zero_containers is the
    prune-safe empty dict."""
    assert _CONTRACT_SCENARIOS["daemon_unreachable"]["payload"] is None
    assert _CONTRACT_SCENARIOS["zero_containers"]["payload"] == {"containers": {}}
