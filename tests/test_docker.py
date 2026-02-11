"""Tests for the Docker metrics collector."""

from unittest.mock import MagicMock, patch

import docker as docker_lib

from fivenines_agent.docker import (
    _image_metadata,
    calculate_cpu_percent,
    calculate_memory_percent,
    calculate_memory_usage,
    docker_containers,
    docker_metrics,
    get_docker_client,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_image(
    tags=None, short_id="sha256:abc123", image_id="sha256:full_id", repo_digests=None
):
    """Return a mock Docker image object."""
    img = MagicMock()
    img.tags = tags
    img.short_id = short_id
    img.id = image_id
    img.attrs = {"RepoDigests": repo_digests or []}
    return img


def _make_stats(
    cpu_total=2000,
    system_cpu=10000,
    mem_usage=500,
    mem_limit=1000,
    mem_stats=None,
    networks=None,
    blkio_stats=None,
):
    """Return a realistic Docker stats dict."""
    s = {
        "cpu_stats": {
            "cpu_usage": {"total_usage": cpu_total},
            "system_cpu_usage": system_cpu,
        },
        "memory_stats": {
            "usage": mem_usage,
            "limit": mem_limit,
            "stats": mem_stats or {},
        },
        "blkio_stats": blkio_stats or {},
    }
    if networks is not None:
        s["networks"] = networks
    return s


def _make_container(
    cid="c1", name="web", image=None, status="running", stats_return=None
):
    """Return a mock Docker container."""
    c = MagicMock()
    c.id = cid
    c.name = name
    c.image = image
    c.status = status
    c.stats.return_value = stats_return or _make_stats()
    return c


# ---------------------------------------------------------------------------
# _image_metadata
# ---------------------------------------------------------------------------


class TestImageMetadata:
    def test_tagged_image(self):
        img = _make_image(
            tags=["postgres:17", "postgres:latest"],
            image_id="sha256:dca7512acaa",
            repo_digests=["postgres@sha256:3f6d"],
        )
        result = _image_metadata(img)
        assert result == {
            "image": "postgres:17",
            "image_id": "sha256:dca7512acaa",
            "image_tags": ["postgres:17", "postgres:latest"],
            "image_repo_digests": ["postgres@sha256:3f6d"],
        }

    def test_untagged_image_falls_back_to_short_id(self):
        img = _make_image(tags=[], short_id="sha256:abc123")
        result = _image_metadata(img)
        assert result["image"] == "sha256:abc123"
        assert result["image_tags"] == []

    def test_none_image(self):
        result = _image_metadata(None)
        assert result == {
            "image": None,
            "image_id": None,
            "image_tags": [],
            "image_repo_digests": [],
        }

    def test_image_without_repo_digests_key(self):
        img = MagicMock()
        img.tags = ["myapp:v1"]
        img.id = "sha256:xyz"
        img.attrs = {}
        result = _image_metadata(img)
        assert result["image_repo_digests"] == []


# ---------------------------------------------------------------------------
# get_docker_client
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# docker_containers
# ---------------------------------------------------------------------------


class TestDockerContainers:
    @patch("fivenines_agent.docker.previous_stats", {})
    @patch("fivenines_agent.docker.get_docker_client")
    def test_first_call_returns_empty(self, mock_get_client):
        """First call has no previous stats so containers_data stays empty."""
        container = _make_container(
            image=_make_image(tags=["nginx:latest"]),
        )
        client = MagicMock()
        client.containers.list.return_value = [container]
        mock_get_client.return_value = client

        result = docker_containers()
        assert result == {}

    @patch("fivenines_agent.docker.previous_stats")
    @patch("fivenines_agent.docker.get_docker_client")
    def test_second_call_returns_full_data(self, mock_get_client, mock_prev):
        """With previous stats, returns full container data with image metadata."""
        prev_stats = _make_stats(cpu_total=1000, system_cpu=5000)
        mock_prev.get.return_value = prev_stats
        mock_prev.__getitem__ = lambda self, key: prev_stats

        img = _make_image(
            tags=["postgres:17"],
            image_id="sha256:dca7512acaa",
            repo_digests=["postgres@sha256:3f6d"],
        )
        cur_stats = _make_stats(
            cpu_total=2000,
            system_cpu=10000,
            mem_usage=500,
            mem_limit=1000,
            blkio_stats={"io": []},
        )
        container = _make_container(
            cid="c1",
            name="db",
            image=img,
            status="running",
            stats_return=cur_stats,
        )

        client = MagicMock()
        client.containers.list.return_value = [container]
        mock_get_client.return_value = client

        result = docker_containers()
        assert "c1" in result
        data = result["c1"]
        assert data["name"] == "db"
        assert data["image"] == "postgres:17"
        assert data["image_id"] == "sha256:dca7512acaa"
        assert data["image_tags"] == ["postgres:17"]
        assert data["image_repo_digests"] == ["postgres@sha256:3f6d"]
        assert data["status"] == "running"
        assert isinstance(data["cpu_percent"], float)
        assert isinstance(data["memory_percent"], float)
        assert isinstance(data["memory_usage"], int)
        assert data["memory_limit"] == 1000
        assert data["blkio_stats"] == {"io": []}
        assert "networks" not in data

    @patch("fivenines_agent.docker.previous_stats")
    @patch("fivenines_agent.docker.get_docker_client")
    def test_with_networks(self, mock_get_client, mock_prev):
        """Networks are included when present in stats."""
        prev_stats = _make_stats(cpu_total=1000, system_cpu=5000)
        mock_prev.get.return_value = prev_stats
        mock_prev.__getitem__ = lambda self, key: prev_stats

        nets = {"eth0": {"rx_bytes": 100, "tx_bytes": 200}}
        cur_stats = _make_stats(cpu_total=2000, system_cpu=10000, networks=nets)
        container = _make_container(
            image=_make_image(tags=["app:v1"]),
            stats_return=cur_stats,
        )
        client = MagicMock()
        client.containers.list.return_value = [container]
        mock_get_client.return_value = client

        result = docker_containers()
        assert result["c1"]["networks"] == nets

    @patch("fivenines_agent.docker.get_docker_client")
    def test_client_none_returns_empty(self, mock_get_client):
        mock_get_client.return_value = None
        assert docker_containers() == {}

    @patch("fivenines_agent.docker.get_docker_client")
    def test_exception_returns_empty(self, mock_get_client):
        client = MagicMock()
        client.containers.list.side_effect = RuntimeError("boom")
        mock_get_client.return_value = client
        assert docker_containers() == {}

    @patch("fivenines_agent.docker.previous_stats")
    @patch("fivenines_agent.docker.get_docker_client")
    def test_none_image_handled(self, mock_get_client, mock_prev):
        """Container with None image does not raise."""
        prev_stats = _make_stats(cpu_total=1000, system_cpu=5000)
        mock_prev.get.return_value = prev_stats
        mock_prev.__getitem__ = lambda self, key: prev_stats

        cur_stats = _make_stats(cpu_total=2000, system_cpu=10000)
        container = _make_container(image=None, stats_return=cur_stats)
        client = MagicMock()
        client.containers.list.return_value = [container]
        mock_get_client.return_value = client

        result = docker_containers()
        assert result["c1"]["image"] is None
        assert result["c1"]["image_id"] is None
        assert result["c1"]["image_tags"] == []
        assert result["c1"]["image_repo_digests"] == []


# ---------------------------------------------------------------------------
# calculate_cpu_percent
# ---------------------------------------------------------------------------


class TestCalculateCpuPercent:
    def test_normal(self):
        stats = _make_stats(cpu_total=2000, system_cpu=10000)
        prev = _make_stats(cpu_total=1000, system_cpu=5000)
        result = calculate_cpu_percent(stats, prev)
        assert result == (1000 / 5000) * 100.0

    def test_zero_delta(self):
        stats = _make_stats(cpu_total=1000, system_cpu=5000)
        prev = _make_stats(cpu_total=1000, system_cpu=5000)
        assert calculate_cpu_percent(stats, prev) == 0.0

    def test_zero_cpu_delta(self):
        stats = _make_stats(cpu_total=1000, system_cpu=10000)
        prev = _make_stats(cpu_total=1000, system_cpu=5000)
        assert calculate_cpu_percent(stats, prev) == 0.0


# ---------------------------------------------------------------------------
# calculate_memory_percent
# ---------------------------------------------------------------------------


class TestCalculateMemoryPercent:
    def test_with_total_inactive_file(self):
        stats = _make_stats(
            mem_usage=500, mem_limit=1000, mem_stats={"total_inactive_file": 100}
        )
        assert calculate_memory_percent(stats) == (400 / 1000) * 100.0

    def test_with_inactive_file(self):
        stats = _make_stats(
            mem_usage=500, mem_limit=1000, mem_stats={"inactive_file": 50}
        )
        assert calculate_memory_percent(stats) == (450 / 1000) * 100.0

    def test_fallback(self):
        stats = _make_stats(mem_usage=500, mem_limit=1000)
        assert calculate_memory_percent(stats) == (500 / 1000) * 100.0


# ---------------------------------------------------------------------------
# calculate_memory_usage
# ---------------------------------------------------------------------------


class TestCalculateMemoryUsage:
    def test_with_total_inactive_file(self):
        stats = _make_stats(mem_usage=500, mem_stats={"total_inactive_file": 100})
        assert calculate_memory_usage(stats) == 400

    def test_with_inactive_file(self):
        stats = _make_stats(mem_usage=500, mem_stats={"inactive_file": 50})
        assert calculate_memory_usage(stats) == 450

    def test_fallback(self):
        stats = _make_stats(mem_usage=500)
        assert calculate_memory_usage(stats) == 500


# ---------------------------------------------------------------------------
# docker_metrics
# ---------------------------------------------------------------------------


class TestDockerMetrics:
    @patch("fivenines_agent.docker.docker_containers")
    def test_wraps_containers(self, mock_containers):
        mock_containers.return_value = {"c1": {"name": "web"}}
        result = docker_metrics(socket_url="unix:///custom.sock")
        mock_containers.assert_called_once_with("unix:///custom.sock")
        assert result == {"containers": {"c1": {"name": "web"}}}

    @patch("fivenines_agent.docker.docker_containers")
    def test_default_socket(self, mock_containers):
        mock_containers.return_value = {}
        result = docker_metrics()
        mock_containers.assert_called_once_with(None)
        assert result == {"containers": {}}
