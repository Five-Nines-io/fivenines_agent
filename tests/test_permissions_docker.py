"""Tests for the Docker socket resolution in PermissionProbe.

_can_access_docker used to hardcode /var/run/docker.sock, which made a reachable
rootless / relocated socket look permanently unavailable. It now resolves the
socket the way the collector does (configured socket_url -> DOCKER_HOST ->
/var/run/docker.sock -> $XDG_RUNTIME_DIR/docker.sock) and reports the path it
actually tried.
"""

from unittest.mock import patch

import pytest

from fivenines_agent.permissions import PermissionProbe


def _probe():
    """A PermissionProbe with just the attributes the docker methods touch, built
    without running the (expensive, host-dependent) full startup probe."""
    p = PermissionProbe.__new__(PermissionProbe)
    p._docker_socket_url = None
    p._current_reason = None
    return p


# --- _docker_socket_from_url ---


def test_socket_from_unix_url_strips_scheme():
    assert PermissionProbe._docker_socket_from_url(
        "unix:///run/user/1000/docker.sock", "src"
    ) == ("/run/user/1000/docker.sock", "src")


def test_socket_from_bare_path():
    assert PermissionProbe._docker_socket_from_url("/var/run/docker.sock", "s") == (
        "/var/run/docker.sock",
        "s",
    )


def test_socket_from_tcp_url_has_no_path():
    assert PermissionProbe._docker_socket_from_url("tcp://10.0.0.1:2375", "s") == (
        None,
        "s",
    )


# --- _resolve_docker_socket resolution order ---


def test_resolve_prefers_configured_socket_url():
    p = _probe()
    p._docker_socket_url = "unix:///custom/docker.sock"
    with patch.dict("os.environ", {"DOCKER_HOST": "unix:///env/docker.sock"}):
        assert p._resolve_docker_socket() == (
            "/custom/docker.sock",
            "configured socket_url",
        )


def test_resolve_falls_back_to_docker_host():
    p = _probe()
    with patch.dict(
        "os.environ", {"DOCKER_HOST": "unix:///run/user/1000/docker.sock"}, clear=False
    ):
        assert p._resolve_docker_socket() == (
            "/run/user/1000/docker.sock",
            "DOCKER_HOST",
        )


def test_resolve_uses_default_socket_when_present():
    p = _probe()
    env = {k: v for k, v in _no_docker_env().items()}
    with patch.dict("os.environ", env, clear=True), patch(
        "fivenines_agent.permissions.os.path.exists", return_value=True
    ):
        assert p._resolve_docker_socket() == ("/var/run/docker.sock", "default socket")


def test_resolve_uses_xdg_runtime_dir_when_no_default():
    p = _probe()
    with patch.dict(
        "os.environ", {"XDG_RUNTIME_DIR": "/run/user/1000"}, clear=True
    ), patch("fivenines_agent.permissions.os.path.exists", return_value=False):
        assert p._resolve_docker_socket() == (
            "/run/user/1000/docker.sock",
            "XDG_RUNTIME_DIR (rootless)",
        )


def test_resolve_defaults_when_nothing_resolves():
    p = _probe()
    with patch.dict("os.environ", {}, clear=True), patch(
        "fivenines_agent.permissions.os.path.exists", return_value=False
    ):
        assert p._resolve_docker_socket() == ("/var/run/docker.sock", "default socket")


def _no_docker_env():
    import os

    return {
        k: v
        for k, v in os.environ.items()
        if k not in ("DOCKER_HOST", "XDG_RUNTIME_DIR")
    }


# --- _can_access_docker ---


def test_can_access_tcp_endpoint_assumed_reachable():
    p = _probe()
    p._docker_socket_url = "tcp://10.0.0.1:2375"
    assert p._can_access_docker() is True
    assert p._current_reason is None  # no os.access check, no reason recorded


def test_can_access_missing_socket_reports_path_and_source():
    p = _probe()
    p._docker_socket_url = "/run/user/1000/docker.sock"
    with patch("fivenines_agent.permissions.os.path.exists", return_value=False):
        assert p._can_access_docker() is False
    assert "/run/user/1000/docker.sock" in p._current_reason
    assert "configured socket_url" in p._current_reason


def test_can_access_readable_writable_socket_is_available():
    p = _probe()
    p._docker_socket_url = "/var/run/docker.sock"
    with patch("fivenines_agent.permissions.os.path.exists", return_value=True), patch(
        "fivenines_agent.permissions.os.access", return_value=True
    ):
        assert p._can_access_docker() is True


def test_can_access_present_but_not_writable_reports_bits():
    p = _probe()
    p._docker_socket_url = "/var/run/docker.sock"

    def _access(path, mode):
        import os

        return mode == os.R_OK  # readable but not writable

    with patch("fivenines_agent.permissions.os.path.exists", return_value=True), patch(
        "fivenines_agent.permissions.os.access", side_effect=_access
    ):
        assert p._can_access_docker() is False
    assert "readable=True, writable=False" in p._current_reason


def test_unsupported_endpoint_scheme_is_refused():
    """A garbage or typo'd socket_url must NOT report the capability available.

    The non-unix branch assumes reachable (Ceph light-probe precedent: a
    transient network failure must not disable a collector). But that must apply
    only to endpoints docker-py can actually dial -- otherwise a malformed
    backend value reports Docker as available on a host with no Docker at all."""
    p = _probe()
    p._docker_socket_url = "htp:/typo.example:2375"
    assert p._can_access_docker() is False
    assert "unsupported Docker endpoint" in p._current_reason


@pytest.mark.parametrize(
    "endpoint",
    ["tcp://10.0.0.1:2375", "ssh://user@host", "npipe:////./pipe/docker_engine"],
)
def test_supported_remote_schemes_are_assumed_reachable(endpoint):
    p = _probe()
    p._docker_socket_url = endpoint
    assert p._can_access_docker() is True
    assert p._current_reason is None


def test_http_unix_scheme_is_treated_as_a_socket_path():
    """docker-py's own DEFAULT_UNIX_SOCKET is 'http+unix://...', so the probe
    must resolve it to a path rather than mistake it for a remote endpoint."""
    assert PermissionProbe._docker_socket_from_url(
        "http+unix:///var/run/docker.sock", "s"
    ) == ("/var/run/docker.sock", "s")


# --- set_docker_socket_url ---


def test_set_docker_socket_url_updates_probe_target():
    p = _probe()
    p.set_docker_socket_url("unix:///new/docker.sock")
    assert p._docker_socket_url == "unix:///new/docker.sock"
    assert p._resolve_docker_socket()[0] == "/new/docker.sock"


def test_docker_socket_url_exists_before_the_startup_probe_runs():
    """__init__ must set _docker_socket_url BEFORE calling _probe_all(), because
    the startup probe runs _can_access_docker, which reads it. If the assignment
    ever moves below _probe_all() the agent dies with AttributeError on boot --
    and no other test catches it: every full-probe test patches
    _can_access_docker out."""
    seen = {}

    def _spy(self):
        # AttributeError here if the attribute is initialised after _probe_all.
        seen["socket_url"] = self._docker_socket_url

    with patch.object(PermissionProbe, "_probe_all", _spy):
        PermissionProbe()

    assert seen["socket_url"] is None
