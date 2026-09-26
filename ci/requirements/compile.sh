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
