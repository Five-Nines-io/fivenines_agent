#!/bin/sh
# Regenerate the hash-pinned build-tool requirements from their .in files.
# Resolution is universal (every OS, glibc and musl, Python 3.10+), because the
# same files serve the manylinux, Alpine and Windows builds. Every install from
# them uses `pip install --require-hashes --no-deps`, so a file that no longer
# matches what the index serves fails the build instead of installing it.
#
# Usage: sh ci/requirements/compile.sh    (from anywhere; needs uv)
set -eu
cd "$(dirname "$0")"

compile() {
    name="$1"
    shift
    uv pip compile "$name.in" --output-file "$name.txt" \
        --universal --python-version 3.10 --generate-hashes \
        --custom-compile-command "sh ci/requirements/compile.sh" --quiet "$@"
}

compile build-tools
compile libvirt-build
# libvirt-python has no dependencies, and its metadata can only be read by
# building it against libvirt; --no-deps pins the sdist without building it.
compile libvirt-python --no-deps
compile libvirt-python-alpine --no-deps
# proxmoxer, pynvml and nvidia-ml-py have no other dependencies, and --no-deps
# keeps uv from re-pinning anything poetry.lock already installs on Alpine.
compile alpine-virtualization --no-deps
# pymongo has no musllinux wheel: Alpine builds its sdist against this backend,
# constrained to build-tools.txt so a shared package (packaging, setuptools)
# keeps the version poetry runs with.
compile pymongo-build --constraint build-tools.txt
# --no-deps: dnspython, its one dependency, comes from poetry.lock.
compile pymongo-alpine --no-deps
