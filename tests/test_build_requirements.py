"""Build inputs that must agree with poetry.lock.

py2exe_alpine.sh installs the virtualization group's pure-Python packages
from ci/requirements/alpine-virtualization.txt (its `poetry install` skips
that optional group) and fails the build when a pin is not the version
poetry.lock locks. That check only runs in the Alpine build job, which a pull
request (a Dependabot bump of poetry.lock included) does not trigger, so the
same rule is checked here, where a drift fails the PR instead of main's
Alpine build.
"""

import re
from pathlib import Path


def _locked_packages():
    """{name: (version, {sha256 hashes})} for every package in poetry.lock."""
    text = (REPO_ROOT / "poetry.lock").read_text(encoding="utf-8")
    packages = {}
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^name = "([^"]+)"$', block, re.MULTILINE).group(1)
        version = re.search(r'^version = "([^"]+)"$', block, re.MULTILINE).group(1)
        hashes = set(re.findall(r'hash = "sha256:([0-9a-f]{64})"', block))
        packages[name.lower()] = (version, hashes)
    return packages


def _pinned_packages(path):
    """{name: (version, {sha256 hashes})} from a uv-compiled requirements file."""
    pins = {}
    current = None
    for line in (REPO_ROOT / path).read_text(encoding="utf-8").splitlines():
        pin = re.match(r"^([A-Za-z0-9_.-]+)==(\S+) \\$", line)
        if pin:
            current = pin.group(1).lower()
            pins[current] = (pin.group(2), set())
            continue
        digest = re.match(r"^\s+--hash=sha256:([0-9a-f]{64})", line)
        if digest and current:
            pins[current][1].add(digest.group(1))
    return pins


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_alpine_virtualization_pins_are_poetry_lock_versions_and_hashes():
    locked = _locked_packages()
    pins = _pinned_packages("ci/requirements/alpine-virtualization.txt")
    # The packages py2exe_alpine.sh installs and checks, no more, no less.
    assert set(pins) == {"proxmoxer", "pynvml", "nvidia-ml-py"}
    for name, (version, hashes) in pins.items():
        assert name in locked, f"{name} is not in poetry.lock"
        locked_version, locked_hashes = locked[name]
        assert version == locked_version, (
            f"{name}: alpine-virtualization.txt pins {version}, poetry.lock "
            f"locks {locked_version}; update ci/requirements/"
            "alpine-virtualization.in and run ci/requirements/compile.sh"
        )
        assert hashes and hashes <= locked_hashes, name


def test_alpine_build_checks_and_installs_the_same_packages():
    """The build's poetry.lock check loops over the packages it installs."""
    script = (REPO_ROOT / "py2exe_alpine.sh").read_text(encoding="utf-8")
    loop = re.search(r"^for pkg in ([^;]+); do$", script, re.MULTILINE)
    assert loop, "py2exe_alpine.sh no longer checks its pins against poetry.lock"
    assert set(loop.group(1).split()) == set(
        _pinned_packages("ci/requirements/alpine-virtualization.txt")
    )
    assert (
        "pip install --require-hashes --no-deps --only-binary :all: "
        "-r ci/requirements/alpine-virtualization.txt" in script
    )


def test_alpine_pymongo_pin_is_poetry_lock_version_and_hashes():
    """pymongo has no musllinux wheel: py2exe_alpine.sh builds the sdist this
    file pins before `poetry install`, which skips it only at poetry.lock's
    version (#258). Its build backend is pinned beside it, every file
    hash-checked."""
    locked = _locked_packages()
    pins = _pinned_packages("ci/requirements/pymongo-alpine.txt")
    assert set(pins) == {"pymongo"}
    version, hashes = pins["pymongo"]
    locked_version, locked_hashes = locked["pymongo"]
    assert version == locked_version, (
        f"pymongo-alpine.txt pins {version}, poetry.lock locks {locked_version}; "
        "update ci/requirements/pymongo-alpine.in and run ci/requirements/compile.sh"
    )
    assert hashes and hashes <= locked_hashes
    backend = _pinned_packages("ci/requirements/pymongo-build.txt")
    assert {"hatchling", "hatch-requirements-txt"} <= set(backend)
    assert all(digests for _version, digests in backend.values())
    # A package both files pin keeps build-tools.txt's version (poetry runs
    # with it after this install).
    tools = _pinned_packages("ci/requirements/build-tools.txt")
    for name in set(backend) & set(tools):
        assert backend[name][0] == tools[name][0], name


def test_alpine_build_builds_pymongo_before_the_wheels_only_install():
    script = (REPO_ROOT / "py2exe_alpine.sh").read_text(encoding="utf-8")
    backend = script.index(
        "pip install --require-hashes --no-deps --only-binary :all: "
        "-r ci/requirements/pymongo-build.txt"
    )
    sdist = script.index(
        "pip install --require-hashes --no-deps --no-build-isolation "
        "--no-binary pymongo -r ci/requirements/pymongo-alpine.txt"
    )
    check = script.index(
        'grep -q "^pymongo==${LOCKED} " ci/requirements/pymongo-alpine.txt'
    )
    poetry = script.index('POETRY_INSTALLER_ONLY_BINARY=":all:" poetry install')
    assert check < backend < sdist < poetry
