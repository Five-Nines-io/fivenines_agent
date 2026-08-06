"""Tests for the Docker image OS-package inventory (image vuln scanning phase 1).

The contract fixture (docker_image_inventory_contract_payload.json) is asserted
end-to-end with ONLY the Docker SDK boundary mocked: client.containers.get and
container.get_archive. The remaining tests cover the transient/retry paths, the
parsers, the streaming cap, the coordinator (done-set persistence + in-flight +
per-tick cap), and the uploader thread.
"""

import io
import json
import lzma
import os
import re
import tarfile
import time
from unittest.mock import MagicMock, patch

import docker as docker_lib
import pytest

from fivenines_agent.docker_image_inventory import (
    MAX_FIELD_CHARS,
    MAX_FILE_BYTES,
    MAX_PACKAGES,
    MAX_RESCAN_IMAGES,
    ImageInventoryCoordinator,
    ImageInventoryUploader,
    _ArchiveError,
    _buffer_capped,
    _build_payload,
    _distro_family,
    _parse_apk_installed,
    _parse_dpkg_status,
    _scrub,
    _single_file_bytes,
    apply_rescan_requests,
    build_image_inventory,
    select_and_enqueue,
)
from fivenines_agent.packages import get_packages_hash
from fivenines_agent.synchronization_queue import SynchronizationQueue

_CONTRACT_PATH = os.path.join(
    os.path.dirname(__file__),
    "fixtures",
    "docker_image_inventory_contract_payload.json",
)
with open(_CONTRACT_PATH) as _f:
    _CONTRACT = json.load(_f)
_SCENARIOS = _CONTRACT["scenarios"]


# ---------------------------------------------------------------------------
# SDK boundary mock: build a container whose get_archive tars a described FS.
# ---------------------------------------------------------------------------


def _tar_bytes(arcname, content):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=arcname)
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _symlink_tar(arcname, linkname):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=arcname)
        info.type = tarfile.SYMTYPE
        info.linkname = linkname
        tar.addfile(info)
    return buf.getvalue()


def _chunks(data, size=65536):
    for i in range(0, len(data), size):
        end = i + size
        yield data[i:end]


def _make_container(sdk):
    """A MagicMock container whose get_archive tars the sdk-described filesystem:
    files by path, symlinks (returning a SYMLINK tar entry + absolute linkTarget
    stat), not_found paths (404), and oversized paths (a tar > MAX_FILE_BYTES)."""
    files = sdk.get("files", {})
    symlinks = sdk.get("symlinks", {})
    not_found = set(sdk.get("not_found", []))
    oversized = set(sdk.get("oversized", []))
    api_error = set(sdk.get("api_error", []))
    container = MagicMock()

    def _get_archive(path):
        if path in not_found:
            raise docker_lib.errors.NotFound(f"no such path: {path}")
        if path in api_error:
            raise docker_lib.errors.APIError(f"500 server error for {path}")
        arc = os.path.basename(path)
        if path in symlinks:
            target = symlinks[path]
            rel = os.path.relpath(target, os.path.dirname(path))
            return _chunks(_symlink_tar(arc, rel)), {"name": arc, "linkTarget": target}
        if path in oversized:
            content = b"x" * (MAX_FILE_BYTES + 4096)
            return _chunks(_tar_bytes(arc, content)), {"name": arc, "linkTarget": ""}
        if path in files:
            content = files[path].encode("utf-8")
            return _chunks(_tar_bytes(arc, content)), {"name": arc, "linkTarget": ""}
        raise docker_lib.errors.NotFound(f"no such path: {path}")

    container.get_archive.side_effect = _get_archive
    return container


def _client_for(container):
    client = MagicMock()
    client.containers.get.return_value = container
    return client


# ---------------------------------------------------------------------------
# Contract fixture (cross-repo)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(_SCENARIOS))
def test_contract_fixture_scenarios(name):
    """Each scenario's payload is EXACTLY what build_image_inventory emits for
    that container filesystem, with only the SDK boundary mocked."""
    scenario = _SCENARIOS[name]
    sdk = scenario["sdk"]
    container = _make_container(sdk)
    client = _client_for(container)
    job = {
        "image_id": sdk["image_id"],
        "container_id": sdk["container_id"],
        "socket_url": None,
    }
    with patch(
        "fivenines_agent.docker_image_inventory.get_docker_client",
        return_value=client,
    ):
        out = build_image_inventory(job)
    assert out == scenario["payload"]
    client.containers.get.assert_called_once_with(sdk["container_id"])


@pytest.mark.parametrize("name", sorted(_SCENARIOS))
def test_contract_never_empty_and_clean(name):
    """The one shape a security feature must never emit: 0 packages AND 0 errors
    (renders as a false '0 vulnerabilities')."""
    payload = _SCENARIOS[name]["payload"]
    assert not (payload["packages"] == [] and payload["errors"] == [])


@pytest.mark.parametrize("name", sorted(_SCENARIOS))
def test_contract_hash_matches_packages(name):
    """packages_hash is the host-path get_packages_hash of packages, or null on a
    failure payload."""
    payload = _SCENARIOS[name]["payload"]
    if payload["packages"]:
        assert payload["packages_hash"] == get_packages_hash(payload["packages"])
    else:
        assert payload["packages_hash"] is None


def test_contract_agent_min_version_matches_pyproject():
    """agent_min_version must be a REAL shipped version -- at or below the
    current pyproject version, not a hand-typed twin.

    The server gates FEATURES_SUPPORTED_VERSIONS["docker_image_inventory"] on
    this exact string, so it must be a version some released agent actually
    reports. A hand-typed literal can drift ABOVE any shipped version (the
    server would then gate on a version no agent reports); reading the real
    version catches that. The relation is <=, not ==: this contract's floor is
    frozen at the version the feature shipped in (1.14.0), but once it merges a
    LATER, unrelated feature bumps pyproject above it (TSDB #103 took 1.14.1),
    and an agent at 1.14.1 still supports docker_image_inventory. Only a floor
    GREATER than the shipped version is the bug."""
    pyproject = os.path.join(os.path.dirname(__file__), "..", "pyproject.toml")
    with open(pyproject) as f:
        for line in f:
            if line.startswith("version ="):
                shipped = line.split("=", 1)[1].strip().strip('"')
                break
        else:  # pragma: no cover - pyproject always has a version
            raise AssertionError("no version in pyproject.toml")

    def _parts(v):
        return tuple(int(p) for p in v.split("."))

    assert _parts(_CONTRACT["agent_min_version"]) <= _parts(shipped)


def test_packages_are_sorted_by_name_regardless_of_db_order():
    """packages_hash is ORDER-SENSITIVE (get_packages_hash joins the list as
    given) and is the server's dedupe key, so the sort is load-bearing wire
    contract. Every fixture DB happens to already be in name order, so deleting
    the sort left the whole suite green -- this feeds a reverse-ordered DB so the
    normalization is actually exercised."""
    c = _container_with(
        files={
            "/etc/os-release": "ID=debian\nVERSION_ID=12\n",
            "/var/lib/dpkg/status": (
                "Package: zlib1g\nStatus: install ok installed\nVersion: 1\n"
                "\n"
                "Package: bash\nStatus: install ok installed\nVersion: 2\n"
            ),
        }
    )
    out = _build_payload(c, "sha256:x")
    assert [p["name"] for p in out["packages"]] == ["bash", "zlib1g"]
    assert out["packages_hash"] == get_packages_hash(out["packages"])


def test_every_emitted_error_type_and_step_is_declared_in_the_contract():
    """Drift guard for the CLOSED error enums the server switches on.

    The server vendors this fixture and writes its rendering logic from
    errors_contract. If the agent gains a new errors[].type or .step that the
    contract never declares, the server silently has no case for it -- which for
    package_cap means rendering a TRUNCATED scan as complete. That is the Ceph
    v2 failure shape (ingester keyed on a value set the agent never sent), so
    pin it: every literal the module can emit must be declared."""
    source = open(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "fivenines_agent",
            "docker_image_inventory.py",
        )
    ).read()
    declared_types = set(_CONTRACT["errors_contract"]["type"])
    declared_steps = set(_CONTRACT["errors_contract"]["step"])

    emitted_types = set(re.findall(r'"type":\s*"([a-z_]+)"', source))
    emitted_types |= set(re.findall(r'_ArchiveError\(\s*"([a-z_]+)"', source))
    # Steps appear either inline in an errors[] dict or bound in the
    # (db_path, step, parser) tuple that selects the package-DB family.
    emitted_steps = set(re.findall(r'"step":\s*"([a-z_]+)"', source))
    emitted_steps |= set(re.findall(r'"(dpkg_status|apk_installed)"', source))

    assert (
        emitted_types <= declared_types
    ), f"undeclared errors[].type: {sorted(emitted_types - declared_types)}"
    assert (
        emitted_steps <= declared_steps
    ), f"undeclared errors[].step: {sorted(emitted_steps - declared_steps)}"
    # And the declared set must not rot into fiction either.
    assert declared_types == emitted_types
    assert declared_steps == emitted_steps


def test_shipped_resource_caps_are_pinned():
    """Pin the PRODUCTION cap values. Every cap test injects its own limit, so
    the shipped numbers were unpinned: raising MAX_PACKAGES to 10_000_000 left
    the suite green. These are the agent-side bounds that keep a hostile or
    huge image off the watchdog path."""
    assert MAX_PACKAGES == 2000
    assert MAX_FILE_BYTES == 5 * 1024 * 1024
    assert MAX_FIELD_CHARS == 256
    coordinator = ImageInventoryCoordinator("/tmp/unused-pin-check")
    assert coordinator._max_per_tick == 3
    assert coordinator._max_done == 5000


# ---------------------------------------------------------------------------
# build_image_inventory transient paths (no payload -> retry)
# ---------------------------------------------------------------------------


def test_build_returns_none_when_daemon_unreachable():
    job = {"image_id": "sha256:x", "container_id": "c", "socket_url": None}
    with patch(
        "fivenines_agent.docker_image_inventory.get_docker_client", return_value=None
    ):
        assert build_image_inventory(job) is None


def test_build_returns_none_when_container_gone_before_extraction():
    client = MagicMock()
    client.containers.get.side_effect = docker_lib.errors.NotFound("gone")
    job = {"image_id": "sha256:x", "container_id": "c", "socket_url": None}
    with patch(
        "fivenines_agent.docker_image_inventory.get_docker_client", return_value=client
    ):
        assert build_image_inventory(job) is None


def test_build_returns_none_on_unexpected_container_get_error():
    client = MagicMock()
    client.containers.get.side_effect = RuntimeError("boom")
    job = {"image_id": "sha256:x", "container_id": "c", "socket_url": None}
    with patch(
        "fivenines_agent.docker_image_inventory.get_docker_client", return_value=client
    ):
        assert build_image_inventory(job) is None


def test_build_passes_socket_url_through_to_client_factory():
    container = _make_container(_SCENARIOS["debian_slim"]["sdk"])
    client = _client_for(container)
    captured = {}

    def _factory(socket_url=None):
        captured["socket_url"] = socket_url
        return client

    job = {
        "image_id": "sha256:x",
        "container_id": "c",
        "socket_url": "unix:///run/user/1000/docker.sock",
    }
    with patch(
        "fivenines_agent.docker_image_inventory.get_docker_client", side_effect=_factory
    ):
        build_image_inventory(job)
    assert captured["socket_url"] == "unix:///run/user/1000/docker.sock"


# ---------------------------------------------------------------------------
# _build_payload edge branches not exercised by the fixture
# ---------------------------------------------------------------------------


def _container_with(files=None, symlinks=None, not_found=None, oversized=None):
    return _make_container(
        {
            "files": files or {},
            "symlinks": symlinks or {},
            "not_found": not_found or [],
            "oversized": oversized or [],
        }
    )


def test_os_release_without_id_is_unsupported_distro():
    c = _container_with(files={"/etc/os-release": "PRETTY_NAME=Foo\nVERSION=1\n"})
    out = _build_payload(c, "sha256:x")
    assert out["distro"] is None
    assert out["packages"] == []
    assert out["errors"] == [
        {
            "step": "os_release",
            "type": "unsupported_distro",
            "message": "os-release has no ID field",
        }
    ]


def test_unknown_distro_family_is_unsupported():
    c = _container_with(files={"/etc/os-release": "ID=gentoo\nVERSION_ID=2.14\n"})
    out = _build_payload(c, "sha256:x")
    assert out["distro"] == "gentoo:2.14"
    assert out["packages"] == []
    assert out["errors"] == [
        {
            "step": "distro",
            "type": "unsupported_distro",
            "message": "unsupported distro 'gentoo:2.14'",
        }
    ]


def test_opensuse_is_rpm_unsupported_via_prefix():
    c = _container_with(
        files={"/etc/os-release": 'ID="opensuse-leap"\nVERSION_ID="15.5"\n'}
    )
    out = _build_payload(c, "sha256:x")
    assert out["distro"] == "opensuse-leap:15.5"
    assert out["errors"][0]["type"] == "unsupported_distro"
    assert "RPM-based" in out["errors"][0]["message"]


def test_db_readable_but_zero_packages_is_parse_error():
    """A dpkg status with only a deinstalled entry parses to zero packages: that
    is a parse failure, NOT a clean zero (which would be a false all-clear)."""
    status = (
        "Package: removed-pkg\n" "Status: deinstall ok config-files\n" "Version: 1.0\n"
    )
    c = _container_with(
        files={
            "/etc/os-release": "ID=debian\nVERSION_ID=12\n",
            "/var/lib/dpkg/status": status,
        }
    )
    out = _build_payload(c, "sha256:x")
    assert out["packages"] == []
    assert out["packages_hash"] is None
    assert out["errors"] == [
        {
            "step": "dpkg_status",
            "type": "parse_error",
            "message": "no installed packages parsed from package DB",
        }
    ]


def test_package_cap_truncates_and_records_error():
    many = "".join(
        f"Package: pkg{i:04d}\nStatus: install ok installed\nVersion: 1.0\n\n"
        for i in range(5)
    )
    c = _container_with(
        files={
            "/etc/os-release": "ID=debian\nVERSION_ID=12\n",
            "/var/lib/dpkg/status": many,
        }
    )
    with patch("fivenines_agent.docker_image_inventory.MAX_PACKAGES", 2):
        out = _build_payload(c, "sha256:x")
    assert len(out["packages"]) == 2
    assert out["packages"] == [
        {"name": "pkg0000", "version": "1.0", "ecosystem": None},
        {"name": "pkg0001", "version": "1.0", "ecosystem": None},
    ]
    assert {
        "step": "dpkg_status",
        "type": "package_cap",
        "message": "package list truncated to 2",
    } in out["errors"]


def test_db_api_error_surfaces_in_payload():
    c = MagicMock()

    def _ga(path):
        if path == "/etc/os-release":
            return _chunks(_tar_bytes("os-release", b"ID=debian\nVERSION_ID=12\n")), {
                "linkTarget": ""
            }
        raise docker_lib.errors.APIError("500 server error")

    c.get_archive.side_effect = _ga
    out = _build_payload(c, "sha256:x")
    assert out["distro"] == "debian:12"
    assert out["packages"] == []
    assert out["errors"] == [
        {
            "step": "dpkg_status",
            "type": "api_error",
            "message": "/var/lib/dpkg/status: daemon error",
        }
    ]


def test_symlink_target_not_found_is_recorded():
    c = _container_with(
        symlinks={"/etc/os-release": "/usr/lib/os-release"},
        not_found=["/usr/lib/os-release"],
    )
    out = _build_payload(c, "sha256:x")
    assert out["distro"] is None
    assert out["errors"] == [
        {
            "step": "os_release",
            "type": "not_found",
            "message": "symlink target /usr/lib/os-release not found in image",
        }
    ]


def test_symlink_chain_not_followed_twice_is_parse_error():
    """Only ONE symlink hop is followed. A symlink pointing at another symlink
    yields a tar with no regular file -> parse_error (never a silent empty)."""
    c = _container_with(
        symlinks={
            "/etc/os-release": "/a",
            "/a": "/b",
        }
    )
    out = _build_payload(c, "sha256:x")
    assert out["distro"] is None
    assert out["errors"] == [
        {
            "step": "os_release",
            "type": "parse_error",
            "message": "no readable file in archive for /etc/os-release",
        }
    ]


def test_unexpected_stream_error_is_api_error():
    """An error while iterating the archive byte-stream (not from get_archive
    itself) maps to api_error, not an unhandled crash."""

    def _boom():
        yield b"partial"
        raise OSError("connection reset")

    c = MagicMock()
    c.get_archive.side_effect = lambda path: (_boom(), {"linkTarget": ""})
    out = _build_payload(c, "sha256:x")
    # os-release read fails while streaming -> api_error at the os_release step.
    assert out["errors"][0]["step"] == "os_release"
    assert out["errors"][0]["type"] == "api_error"


def test_file_cap_aborts_mid_stream_not_after():
    """The 5 MB cap is enforced WHILE streaming (running buf.tell() check), not
    after the archive is buffered. An implementation that joined the chunks first
    would drain the whole stream -- and OOM on a real multi-GB layer -- while
    still producing a file_over_cap error, so the error type alone does not prove
    the invariant; the number of chunks actually pulled does."""
    chunk = b"x" * 65536
    cap_chunks = MAX_FILE_BYTES // len(chunk)
    consumed = {"n": 0}

    def _endless():
        for _ in range(cap_chunks * 4):
            consumed["n"] += 1
            yield chunk
        raise AssertionError("stream was drained instead of aborted mid-way")

    c = MagicMock()
    c.get_archive.side_effect = lambda path: (_endless(), {"linkTarget": ""})
    out = _build_payload(c, "sha256:x")
    assert out["errors"][0]["type"] == "file_over_cap"
    # Stopped on the first chunk that crossed the cap, not after the stream ended.
    assert consumed["n"] == cap_chunks + 1


def test_tar_member_that_cannot_be_extracted_is_parse_error():
    """Defensive: a tar whose only regular-file member yields None from
    extractfile must be reported as parse_error, never as an empty-and-clean
    payload."""
    bits = _tar_bytes("os-release", b"ID=debian\nVERSION_ID=12\n")
    c = MagicMock()
    c.get_archive.side_effect = lambda path: (_chunks(bits), {"linkTarget": ""})
    member = MagicMock()
    member.isfile.return_value = True
    fake_tar = MagicMock()
    fake_tar.getmembers.return_value = [member]
    fake_tar.extractfile.return_value = None

    with patch("fivenines_agent.docker_image_inventory.tarfile.open") as mock_open:
        mock_open.return_value.__enter__.return_value = fake_tar
        out = _build_payload(c, "sha256:x")

    assert out["packages"] == []
    assert out["errors"] == [
        {
            "step": "os_release",
            "type": "parse_error",
            "message": "no readable file in archive for /etc/os-release",
        }
    ]


def test_non_docker_get_archive_error_is_api_error():
    """A non-docker exception from get_archive itself (e.g. a connection reset)
    maps to api_error, not an unhandled crash."""
    c = MagicMock()
    c.get_archive.side_effect = ConnectionResetError("reset")
    out = _build_payload(c, "sha256:x")
    assert out["errors"] == [
        {
            "step": "os_release",
            "type": "api_error",
            "message": "/etc/os-release: read error",
        }
    ]


def test_non_dict_stat_is_tolerated():
    """A get_archive returning a non-dict stat (defensive) is treated as no
    linkTarget rather than crashing."""
    c = MagicMock()
    c.get_archive.side_effect = lambda path: (
        (
            _chunks(_tar_bytes("os-release", b"ID=alpine\nVERSION_ID=3.19\n")),
            None,
        )
        if path == "/etc/os-release"
        else (
            _chunks(_tar_bytes("installed", b"P:musl\nV:1.2.4-r2\n")),
            None,
        )
    )
    out = _build_payload(c, "sha256:x")
    assert out["distro"] == "alpine:3.19"
    assert out["packages"] == [
        {"name": "musl", "version": "1.2.4-r2", "ecosystem": None}
    ]


# ---------------------------------------------------------------------------
# Parsers + small helpers
# ---------------------------------------------------------------------------


def test_parse_dpkg_status_filters_and_skips_continuations():
    text = (
        "Package: a\nStatus: install ok installed\nVersion: 1\n"
        "Description: x\n Version: 9 (continuation, skipped)\n"
        "\n"
        "Package: b\nStatus: hold ok installed\nVersion: 2\n"  # not 'install ok installed'
        "\n"
        "Package: c\nStatus: install ok installed\nVersion: 3\n"
    )
    pkgs, truncated = _parse_dpkg_status(text)
    assert pkgs == [
        {"name": "a", "version": "1", "ecosystem": None},
        {"name": "c", "version": "3", "ecosystem": None},
    ]
    assert truncated is False


def test_parse_dpkg_status_skips_partial_and_garbage():
    text = (
        "Package: a\nStatus: install ok installed\nVersion: 1\n"
        "\n"
        "Package: nover\nStatus: install ok installed\n"  # no Version
        "\n"
        "just garbage\nno fields here\n"
    )
    assert _parse_dpkg_status(text) == (
        [{"name": "a", "version": "1", "ecosystem": None}],
        False,
    )


def test_parse_apk_installed():
    # Leading + doubled blank lines produce empty stanzas that must be skipped.
    text = "\n\nP:musl\nV:1.2.4-r2\nA:x86_64\n\n\nP:zlib\nV:1.3-r0\n"
    assert _parse_apk_installed(text) == (
        [
            {"name": "musl", "version": "1.2.4-r2", "ecosystem": None},
            {"name": "zlib", "version": "1.3-r0", "ecosystem": None},
        ],
        False,
    )


def test_parse_apk_installed_skips_incomplete_stanza():
    text = "P:musl\nV:1.2.4-r2\n\nP:noversion\nA:x86_64\n"
    assert _parse_apk_installed(text) == (
        [{"name": "musl", "version": "1.2.4-r2", "ecosystem": None}],
        False,
    )


# --- parse-time cap (bounds PEAK memory, not just the emitted list) ---


def _dpkg_blob(n):
    return "".join(
        f"Package: pkg{i:05d}\nStatus: install ok installed\nVersion: 1\n\n"
        for i in range(n)
    )


def test_compressed_tar_is_refused_not_transparently_inflated():
    """Decompression-bomb regression.

    tarfile.open's default mode "r" means "r:*" -- TRANSPARENT DECOMPRESSION --
    which defeats the byte cap entirely, because the cap is applied to the bytes
    on the wire. Measured on the original code: a 45,944-byte xz tar passed the
    5 MB cap and read() returned 314,583,040 bytes (~300 MiB RSS). The daemon
    always sends an uncompressed tar, so mode="r:" loses nothing legitimate."""
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w") as tar:
        payload = b"\0" * (16 * 1024 * 1024)
        info = tarfile.TarInfo("os-release")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    bomb = lzma.compress(inner.getvalue())
    assert len(bomb) < MAX_FILE_BYTES, "bomb must pass the byte cap to be a real test"

    with pytest.raises(_ArchiveError) as excinfo:
        _single_file_bytes(_buffer_capped(iter([bomb])))
    assert excinfo.value.type == "parse_error"


def test_member_larger_than_the_cap_is_refused():
    """Defense in depth: even if an oversized member reaches the tar layer, the
    read is bounded rather than slurping it whole."""
    buf = io.BytesIO(_tar_bytes("os-release", b"x" * 64))
    with patch("fivenines_agent.docker_image_inventory.MAX_FILE_BYTES", 8):
        with pytest.raises(_ArchiveError) as excinfo:
            _single_file_bytes(buf)
    assert excinfo.value.type == "file_over_cap"


def test_dpkg_parser_skips_blank_stanzas():
    text = (
        "\n\n"
        "Package: a\nStatus: install ok installed\nVersion: 1\n"
        "\n\n"
        "Package: b\nStatus: install ok installed\nVersion: 2\n"
    )
    packages, truncated = _parse_dpkg_status(text)
    assert [p["name"] for p in packages] == ["a", "b"]
    assert truncated is False


def test_apk_entry_that_scrubs_to_empty_is_dropped():
    """Same honesty-contract guard as dpkg, on the apk path."""
    text = "P:musl\nV:1.2\n\nP:\x00\nV:9.9\n"
    packages, _truncated = _parse_apk_installed(text)
    assert [p["name"] for p in packages] == ["musl"]


def test_parser_stops_at_the_cap_instead_of_materializing_everything():
    """The cap must bound what the parser BUILDS, not just what it returns.

    Regression for the measured amplification: a hostile image can pack ~580k
    minimal stanzas under the 5 MB file cap, and a post-hoc slice materializes
    all of them (~145 MB) before trimming. Parsing 5000 stanzas with a cap of 10
    must yield 10 -- and the parser must stop early, which is what keeps peak
    allocation at the cap rather than at the file size."""
    packages, truncated = _parse_dpkg_status(_dpkg_blob(5000), limit=10)
    assert len(packages) == 10
    assert truncated is True
    assert packages[0]["name"] == "pkg00000"


def test_parser_reports_not_truncated_at_exactly_the_cap():
    """Exactly `limit` packages is a COMPLETE scan, not a truncated one --
    otherwise a 2000-package image would ship a false package_cap error and the
    server would render a complete scan as under-reported."""
    packages, truncated = _parse_dpkg_status(_dpkg_blob(10), limit=10)
    assert len(packages) == 10
    assert truncated is False


def test_apk_parser_also_caps_during_parsing():
    blob = "".join(f"P:pkg{i:05d}\nV:1\n\n" for i in range(500))
    packages, truncated = _parse_apk_installed(blob, limit=5)
    assert len(packages) == 5
    assert truncated is True


# --- scrubbing ---


def test_scrub_removes_nul_and_replacement_char():
    assert _scrub("open\x00ssl") == "openssl"
    assert _scrub("v\ufffd1.0") == "v1.0"


def test_scrub_removes_all_control_characters():
    """Not just NUL: a newline or ANSI escape in an image-controlled package name
    would be injected into the payload, the dashboard, and the agent's own log
    lines. C0 and C1 both go."""
    assert _scrub("bad\nname\r\tx") == "badnamex"
    assert _scrub("esc\x1b[31mred") == "esc[31mred"
    assert _scrub("c1\x85next") == "c1next"


def test_scrub_bounds_field_length():
    assert len(_scrub("a" * 5000)) == MAX_FIELD_CHARS


def test_scrub_applied_to_names_and_versions_from_bytes():
    # invalid UTF-8 byte 0xff decodes to U+FFFD then is scrubbed; NUL stripped.
    text = "P:mu\x00sl\nV:1.2\n"
    assert _parse_apk_installed(text) == (
        [{"name": "musl", "version": "1.2", "ecosystem": None}],
        False,
    )


def test_entry_whose_name_scrubs_to_empty_is_dropped_not_shipped():
    """Honesty-contract bypass regression.

    `Package: \\x00` is TRUTHY raw but scrubs to "". Emitting it would ship a
    nameless package AND make `packages` non-empty, which suppresses the
    never-empty-and-clean guard -- a false all-clear on a security feature. The
    entry must be dropped so the guard still fires."""
    text = "Package: \x00\nStatus: install ok installed\nVersion: 1.0\n"
    assert _parse_dpkg_status(text) == ([], False)

    c = _container_with(
        files={
            "/etc/os-release": "ID=debian\nVERSION_ID=12\n",
            "/var/lib/dpkg/status": text,
        }
    )
    out = _build_payload(c, "sha256:x")
    assert all(p["name"] and p["version"] for p in out["packages"])
    assert not (out["packages"] == [] and out["errors"] == [])
    assert out["errors"][0]["type"] == "parse_error"


@pytest.mark.parametrize(
    "distro,family",
    [
        ("debian:12", "dpkg"),
        ("ubuntu:22.04", "dpkg"),
        ("alpine:3.19", "apk"),
        ("almalinux:9", "rpm"),
        ("rhel:8", "rpm"),
        ("opensuse-tumbleweed:latest", "rpm"),
        ("gentoo:2", None),
    ],
)
def test_distro_family(distro, family):
    assert _distro_family(distro) == family


def test_archive_error_carries_type_and_message():
    e = _ArchiveError("not_found", "gone")
    assert e.type == "not_found"
    assert e.message == "gone"
    assert str(e) == "gone"


# ---------------------------------------------------------------------------
# ImageInventoryCoordinator
# ---------------------------------------------------------------------------


def _coord(tmp_path, **kw):
    return ImageInventoryCoordinator(os.path.join(str(tmp_path), "done"), **kw)


def test_coordinator_selects_up_to_max_per_tick(tmp_path):
    c = _coord(tmp_path, max_per_tick=2)
    jobs = c.select_jobs(
        {"sha256:a": "c1", "sha256:b": "c2", "sha256:c": "c3"}, "unix:///s"
    )
    assert len(jobs) == 2
    assert jobs[0] == {
        "image_id": "sha256:a",
        "container_id": "c1",
        "socket_url": "unix:///s",
    }
    assert c._in_flight == {"sha256:a", "sha256:b"}


def test_coordinator_skips_done_in_flight_and_empty(tmp_path):
    c = _coord(tmp_path)
    c.mark_done("sha256:done")
    c._in_flight.add("sha256:busy")
    jobs = c.select_jobs(
        {"sha256:done": "c1", "sha256:busy": "c2", "": "c3", "sha256:new": "c4"},
        None,
    )
    assert [j["image_id"] for j in jobs] == ["sha256:new"]


def test_coordinator_mark_done_persists_and_dedupes(tmp_path):
    path = os.path.join(str(tmp_path), "done")
    c = ImageInventoryCoordinator(path)
    c.select_jobs({"sha256:a": "c1"}, None)
    c.mark_done("sha256:a")
    assert "sha256:a" not in c._in_flight
    with open(path) as f:
        assert f.read() == "sha256:a"
    # idempotent: marking again does not duplicate.
    c.mark_done("sha256:a")
    with open(path) as f:
        assert f.read() == "sha256:a"


def test_coordinator_mark_done_ignores_empty(tmp_path):
    c = _coord(tmp_path)
    c.mark_done(None)
    c.mark_done("")
    assert c._done == []


class _Clock:
    """Controllable clock so backoff is asserted deterministically (no sleeps)."""

    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def test_coordinator_mark_failed_backs_off_then_retries(tmp_path):
    """A failure must not be re-offered on the very next tick. Without backoff a
    failing digest is re-selected every tick forever, and because build_fn runs
    before send_fn each retry re-runs the FULL extraction -- a treadmill during a
    backend outage."""
    clock = _Clock()
    c = _coord(tmp_path, retry_base_seconds=60, now_fn=clock)
    c.select_jobs({"sha256:a": "c1"}, None)
    assert c.select_jobs({"sha256:a": "c1"}, None) == []  # in flight, skipped
    c.mark_failed("sha256:a")
    assert c.select_jobs({"sha256:a": "c1"}, None) == []  # backing off
    clock.advance(59)
    assert c.select_jobs({"sha256:a": "c1"}, None) == []  # still backing off
    clock.advance(2)
    assert c.select_jobs({"sha256:a": "c1"}, None) != []  # retried
    c.mark_failed(None)  # no-op


def test_coordinator_backoff_is_exponential_and_capped(tmp_path):
    clock = _Clock()
    c = _coord(
        tmp_path,
        retry_base_seconds=60,
        max_retry_seconds=300,
        max_attempts=99,
        now_fn=clock,
    )
    delays = []
    for _ in range(5):
        c.mark_failed("sha256:a")
        delays.append(c._next_retry["sha256:a"] - clock.now)
    assert delays == [60, 120, 240, 300, 300]  # doubling, then capped


def test_coordinator_gives_up_after_max_attempts(tmp_path):
    """A permanently-failing digest must stop occupying a per-tick slot, or it
    starves digests that CAN be scanned."""
    clock = _Clock()
    c = _coord(tmp_path, max_attempts=3, retry_base_seconds=1, now_fn=clock)
    for _ in range(3):
        c.mark_failed("sha256:a")
        clock.advance(10_000)
    assert c.select_jobs({"sha256:a": "c1"}, None) == []
    assert "sha256:a" in c._gave_up
    # Give-up is in-memory ONLY: a multi-hour outage must not permanently blind
    # an image, so a restart re-tries it.
    fresh = ImageInventoryCoordinator(c.state_path)
    assert fresh.select_jobs({"sha256:a": "c1"}, None) != []


def test_coordinator_success_clears_the_failure_history(tmp_path):
    clock = _Clock()
    c = _coord(tmp_path, max_attempts=3, now_fn=clock)
    c.mark_failed("sha256:a")
    c.mark_failed("sha256:a")
    c.mark_done("sha256:a")
    assert "sha256:a" not in c._attempts
    assert "sha256:a" not in c._next_retry


def test_queue_full_shed_does_not_count_as_a_failed_attempt(tmp_path):
    """Backpressure is not failure. select_and_enqueue sheds when the queue is
    full, but the extraction never ran -- counting it would let a busy queue
    exhaust max_attempts and give up on a digest that was never tried."""
    clock = _Clock()
    c = _coord(tmp_path, max_attempts=2, now_fn=clock)
    q = SynchronizationQueue(maxsize=1)
    q.put({"image_id": "old"})  # full
    for _ in range(5):
        assert select_and_enqueue(c, q, {"sha256:a": "c1"}, None) == []
    assert c._attempts == {}
    assert c._gave_up == set()
    # Still immediately selectable -- no backoff was scheduled.
    assert c.select_jobs({"sha256:a": "c1"}, None) != []


def test_coordinator_release_is_a_noop_for_empty_id(tmp_path):
    c = _coord(tmp_path)
    c.release(None)
    c.release("")
    assert c._in_flight == set()


def test_coordinator_bounds_done_set_with_fifo_eviction(tmp_path):
    path = os.path.join(str(tmp_path), "done")
    c = ImageInventoryCoordinator(path, max_done=2)
    for d in ("sha256:1", "sha256:2", "sha256:3"):
        c.mark_done(d)
    assert c._done == ["sha256:2", "sha256:3"]
    assert "sha256:1" not in c._done_set
    with open(path) as f:
        assert f.read().split("\n") == ["sha256:2", "sha256:3"]


def test_coordinator_persistence_survives_restart(tmp_path):
    path = os.path.join(str(tmp_path), "done")
    c = ImageInventoryCoordinator(path)
    c.mark_done("sha256:a")
    fresh = ImageInventoryCoordinator(path)
    assert fresh.select_jobs({"sha256:a": "c1"}, None) == []  # already done


def test_coordinator_load_error_degrades_to_empty(tmp_path):
    # A directory as the state path -> read raises -> no baseline (fires fresh).
    d = os.path.join(str(tmp_path), "as_dir")
    os.mkdir(d)
    c = ImageInventoryCoordinator(d)
    assert c._done == []


def test_coordinator_persist_failure_is_best_effort(tmp_path):
    bad = os.path.join(str(tmp_path), "missing", "done")  # parent absent -> write fails
    c = ImageInventoryCoordinator(bad)
    c.mark_done("sha256:a")  # must not raise
    assert "sha256:a" in c._done_set  # in-memory still recorded


# ---------------------------------------------------------------------------
# select_and_enqueue glue
# ---------------------------------------------------------------------------


def test_select_and_enqueue_puts_jobs(tmp_path):
    q = SynchronizationQueue(maxsize=10)
    c = _coord(tmp_path)
    jobs = select_and_enqueue(c, q, {"sha256:a": "c1", "sha256:b": "c2"}, "unix:///s")
    assert len(jobs) == 2
    assert q.qsize() == 2


def test_select_and_enqueue_sheds_and_releases_when_full(tmp_path):
    q = SynchronizationQueue(maxsize=1)
    q.put({"image_id": "old"})  # queue now full
    c = _coord(tmp_path)
    jobs = select_and_enqueue(c, q, {"sha256:a": "c1"}, None)
    assert jobs == []
    assert q.qsize() == 1  # new job shed, old not evicted
    # slot released -> the digest can be selected again next tick, with no
    # backoff (a shed is backpressure, not a failed extraction attempt)
    assert c.select_jobs({"sha256:a": "c1"}, None) != []


# ---------------------------------------------------------------------------
# Server-driven re-inventory: config["rescan_images"] (server issue #676)
# ---------------------------------------------------------------------------


def test_reset_reopens_a_done_digest(tmp_path):
    """The whole point: an api_error extraction still ends in a 200, so the
    digest is done forever and the image reads 'not scannable' for good. The
    server's directive is the only thing that can re-offer it."""
    c = _coord(tmp_path)
    c.mark_done("sha256:a")
    assert c.select_jobs({"sha256:a": "c1"}, None) == []

    assert c.reset(["sha256:a"]) == ["sha256:a"]
    assert c.select_jobs({"sha256:a": "c1"}, None) != []


def test_reset_persists_so_a_restart_does_not_resurrect_done(tmp_path):
    path = os.path.join(str(tmp_path), "done")
    c = ImageInventoryCoordinator(path)
    c.mark_done("sha256:a")
    c.reset(["sha256:a"])

    fresh = ImageInventoryCoordinator(path)
    assert fresh.select_jobs({"sha256:a": "c1"}, None) != []


def test_reset_clears_gave_up(tmp_path):
    """Give-up is what would otherwise make the server's directive a no-op on a
    digest that failed locally. Eligibility timing is the ladder's job, asserted
    separately in test_reset_of_a_given_up_digest_stays_on_the_retry_ladder."""
    clock = _Clock()
    c = _coord(tmp_path, max_attempts=2, retry_base_seconds=1, now_fn=clock)
    c.mark_failed("sha256:a")
    c.mark_failed("sha256:a")
    assert "sha256:a" in c._gave_up

    assert c.reset(["sha256:a"]) == ["sha256:a"]
    assert "sha256:a" not in c._gave_up
    clock.advance(3600)
    assert c.select_jobs({"sha256:a": "c1"}, None) != []


def test_reset_of_a_clean_done_digest_is_immediate(tmp_path):
    """The main #676 path: an api_error is reported INSIDE a 200, so mark_done
    already cleared the failure history. Nothing should delay the re-scan."""
    clock = _Clock()
    c = _coord(tmp_path, retry_base_seconds=60, now_fn=clock)
    c.mark_done("sha256:a")

    c.reset(["sha256:a"])
    assert c.select_jobs({"sha256:a": "c1"}, None) != []  # no delay at all


def test_reset_of_a_given_up_digest_stays_on_the_retry_ladder(tmp_path):
    """THE anti-treadmill guard, and the reason reset() re-arms _next_retry.

    When the POST itself is what fails, the server never learns and keeps
    re-requesting the digest on EVERY tick. If a re-open made a given-up digest
    immediately eligible, each tick would run a full archive fetch + tar parse,
    fail, and give up again -- forever. Re-arming the ladder caps that at one
    extraction per backoff window."""
    clock = _Clock()
    c = _coord(tmp_path, max_attempts=3, retry_base_seconds=60, now_fn=clock)
    for _ in range(3):
        c.mark_failed("sha256:a")
        clock.advance(10_000)
    assert "sha256:a" in c._gave_up

    assert c.reset(["sha256:a"]) == ["sha256:a"]
    assert "sha256:a" not in c._gave_up
    # Re-opened, but NOT immediately eligible: 3 prior failures -> 60 * 2^2.
    assert c.select_jobs({"sha256:a": "c1"}, None) == []
    clock.advance(239)
    assert c.select_jobs({"sha256:a": "c1"}, None) == []
    clock.advance(2)
    assert c.select_jobs({"sha256:a": "c1"}, None) != []


def test_repeated_reset_of_a_failing_digest_cannot_extract_every_tick(tmp_path):
    """The treadmill, driven end-to-end: the server re-requests the digest on
    every tick because it never receives a POST. Extractions must be paced by
    the ladder, not by the tick."""
    clock = _Clock()
    c = _coord(tmp_path, max_attempts=2, retry_base_seconds=60, now_fn=clock)
    c.mark_done("sha256:a")

    selections = 0
    for _ in range(20):  # 20 ticks, 30s apart
        apply_rescan_requests(c, {"rescan_images": ["sha256:a"]})
        jobs = c.select_jobs({"sha256:a": "c1"}, None)
        if jobs:
            selections += 1
            c.mark_failed("sha256:a")  # the POST never lands
        clock.advance(30)

    # 10 minutes of ticks: a handful of paced attempts, not one per tick.
    assert 1 <= selections <= 4, selections


def test_reset_skips_an_in_flight_digest(tmp_path):
    """Clearing in-flight would let the same extraction be enqueued twice."""
    c = _coord(tmp_path)
    c.select_jobs({"sha256:a": "c1"}, None)  # marks in-flight
    assert c.reset(["sha256:a"]) == []
    assert "sha256:a" in c._in_flight


def test_reset_is_a_noop_for_an_unknown_digest(tmp_path):
    """A digest neither done nor given up is already owned by the normal
    selection path -- the server asking for it must not change anything."""
    c = _coord(tmp_path)
    assert c.reset(["sha256:unknown"]) == []
    assert c._done == []


def test_reset_handles_empty_and_duplicate_input(tmp_path):
    c = _coord(tmp_path)
    assert c.reset([]) == []
    assert c.reset(None) == []
    c.mark_done("sha256:a")
    # A repeated digest must be reported once, not twice.
    assert c.reset(["sha256:a", "sha256:a", ""]) == ["sha256:a"]


def test_reset_only_rewrites_done_when_something_was_removed(tmp_path):
    """A gave-up-only reset touches no persisted state, so it must not pay a
    disk write on the collection loop."""
    c = _coord(tmp_path, max_attempts=1)
    c.mark_failed("sha256:a")  # -> gave_up, never done
    with patch.object(c, "_persist") as persist:
        assert c.reset(["sha256:a"]) == ["sha256:a"]
        persist.assert_not_called()


def test_apply_rescan_requests_resets_and_returns(tmp_path):
    c = _coord(tmp_path)
    c.mark_done("sha256:a")
    reopened = apply_rescan_requests(c, {"rescan_images": ["sha256:a"]})
    assert reopened == ["sha256:a"]
    assert c.select_jobs({"sha256:a": "c1"}, None) != []


@pytest.mark.parametrize(
    "config",
    [
        {},
        {"rescan_images": None},
        {"rescan_images": "sha256:a"},  # a bare string is not a list
        {"rescan_images": {"sha256:a": 1}},
        {"rescan_images": 42},
        None,
    ],
)
def test_apply_rescan_requests_ignores_malformed_config(tmp_path, config):
    """Untrusted input off the wire: anything that is not a list of non-empty
    strings is ignored rather than raising."""
    c = _coord(tmp_path)
    c.mark_done("sha256:a")
    assert apply_rescan_requests(c, config) == []
    assert c.select_jobs({"sha256:a": "c1"}, None) == []  # still done


def test_apply_rescan_requests_ignores_a_list_of_only_junk(tmp_path):
    """A well-formed list whose every entry is unusable must short-circuit
    without touching the coordinator at all."""
    c = _coord(tmp_path)
    with patch.object(c, "reset") as reset:
        assert apply_rescan_requests(c, {"rescan_images": [None, "", "  ", 3]}) == []
        reset.assert_not_called()


def test_apply_rescan_requests_drops_non_string_and_blank_entries(tmp_path):
    c = _coord(tmp_path)
    c.mark_done("sha256:a")
    reopened = apply_rescan_requests(
        c, {"rescan_images": [None, 7, "", "   ", {"x": 1}, "sha256:a"]}
    )
    assert reopened == ["sha256:a"]


def test_apply_rescan_requests_caps_the_list(tmp_path):
    """A malformed or hostile config must not re-open the whole done set."""
    c = _coord(tmp_path, max_done=1000)
    digests = [f"sha256:{i}" for i in range(MAX_RESCAN_IMAGES + 5)]
    for d in digests:
        c.mark_done(d)
    reopened = apply_rescan_requests(c, {"rescan_images": digests})
    assert len(reopened) == MAX_RESCAN_IMAGES


# ---------------------------------------------------------------------------
# ImageInventoryUploader thread
# ---------------------------------------------------------------------------


def _drain(q, timeout=2.0):
    """Wait for the uploader to finish every queued job, with a deadline.

    A bare Queue.join() has no timeout: if a regression ever drops the
    task_done() in the uploader's finally, join() blocks forever and the whole
    pytest process hangs instead of reporting a failure -- a CI timeout rather
    than a red test. Fail loudly instead."""
    deadline = time.monotonic() + timeout
    while q.unfinished_tasks and time.monotonic() < deadline:
        time.sleep(0.005)
    assert (
        not q.unfinished_tasks
    ), "uploader never drained the queue (task_done missing?)"


def _run_uploader(build_fn, send_fn, jobs, **cbs):
    q = SynchronizationQueue(maxsize=50)
    up = ImageInventoryUploader(q, build_fn, send_fn, **cbs)
    up.start()
    for j in jobs:
        q.put(j)
    q.put(None)  # shutdown sentinel
    up.join(timeout=2)
    assert not up.is_alive()


def test_uploader_builds_sends_and_marks_done():
    sent, done = [], []
    _run_uploader(
        lambda job: {"image_id": job["image_id"]},
        lambda payload: sent.append(payload) or {"status": "ok"},
        [{"image_id": "sha256:a"}],
        on_success=done.append,
        on_failure=lambda i: done.append(("fail", i)),
    )
    assert sent == [{"image_id": "sha256:a"}]
    assert done == ["sha256:a"]


def test_uploader_none_payload_calls_on_failure():
    got = []
    _run_uploader(
        lambda job: None,
        lambda payload: True,
        [{"image_id": "sha256:a"}],
        on_failure=got.append,
    )
    assert got == ["sha256:a"]


def test_uploader_send_false_calls_on_failure():
    got = []
    _run_uploader(
        lambda job: {"image_id": job["image_id"]},
        lambda payload: None,  # non-200 -> transient
        [{"image_id": "sha256:a"}],
        on_failure=got.append,
    )
    assert got == ["sha256:a"]


def test_uploader_isolates_build_and_send_exceptions():
    got = []

    def build(job):
        if job["image_id"] == "boom":
            raise ValueError("x")
        return {"image_id": job["image_id"]}

    def send(payload):
        if payload["image_id"] == "sha256:senderr":
            raise RuntimeError("net down")
        return {"status": "ok"}

    _run_uploader(
        build,
        send,
        [
            {"image_id": "boom"},
            {"image_id": "sha256:senderr"},
            {"image_id": "sha256:ok"},
        ],
        on_success=lambda i: got.append(("ok", i)),
        on_failure=lambda i: got.append(("fail", i)),
    )
    assert got == [("fail", "boom"), ("fail", "sha256:senderr"), ("ok", "sha256:ok")]


def test_uploader_default_callbacks_do_not_crash():
    # No on_success/on_failure provided -> default no-op lambdas are exercised.
    _run_uploader(
        lambda job: {"image_id": job["image_id"]},
        lambda payload: True,
        [{"image_id": "sha256:a"}],
    )
    _run_uploader(lambda job: None, lambda payload: True, [{"image_id": "sha256:b"}])


def test_uploader_stop_sets_event():
    up = ImageInventoryUploader(SynchronizationQueue(), lambda j: None, lambda p: True)
    assert not up._stop_event.is_set()
    up.stop()
    assert up._stop_event.is_set()


def test_uploader_run_exits_on_stop_without_a_sentinel():
    """Second exit path: the stop_event ends the loop even if no None sentinel
    is ever pushed, so a stopped uploader cannot pin a non-daemon thread."""
    q = SynchronizationQueue(maxsize=5)
    up = ImageInventoryUploader(q, lambda job: None, lambda payload: True)
    up.stop()  # stopped BEFORE start -> run() must return without blocking
    up.start()
    up.join(timeout=2)
    assert not up.is_alive()


def test_coordinator_and_uploader_close_the_retry_loop(tmp_path):
    """The composition the Agent builds (on_success=mark_done,
    on_failure=mark_failed) end to end: a non-200 releases the digest so a later
    tick retries it, a 200 retires it forever -- including across a restart. A
    swap of the two callbacks would either re-extract every image on every tick
    or never retry a transient failure."""
    clock = _Clock()
    coord = _coord(tmp_path, retry_base_seconds=60, now_fn=clock)
    q = SynchronizationQueue(maxsize=10)
    outcome = {"ok": None}  # non-200 first
    up = ImageInventoryUploader(
        q,
        lambda job: {"image_id": job["image_id"]},
        lambda payload: outcome["ok"],
        on_success=coord.mark_done,
        on_failure=coord.mark_failed,
    )
    up.start()
    try:
        assert select_and_enqueue(coord, q, {"sha256:a": "c1"}, None) != []
        _drain(q)
        assert "sha256:a" not in coord._done_set  # not retired on a failure

        outcome["ok"] = {"status": "ok"}
        # Selectable again only because mark_failed released the in-flight slot
        # -- and only once its backoff window has elapsed.
        assert select_and_enqueue(coord, q, {"sha256:a": "c1"}, None) == []
        clock.advance(61)
        assert select_and_enqueue(coord, q, {"sha256:a": "c1"}, None) != []
        _drain(q)
        assert "sha256:a" in coord._done_set
        assert select_and_enqueue(coord, q, {"sha256:a": "c1"}, None) == []
        # done survives a restart: a fresh coordinator re-reads the state file.
        fresh = ImageInventoryCoordinator(coord.state_path)
        assert fresh.select_jobs({"sha256:a": "c1"}, None) == []
    finally:
        up.stop()
        q.put(None)
        up.join(timeout=2)


def test_uploader_non_dict_job_id_is_none():
    got = []
    _run_uploader(
        lambda job: None,
        lambda p: True,
        ["not-a-dict"],
        on_failure=lambda i: got.append(i),
    )
    assert got == [None]
