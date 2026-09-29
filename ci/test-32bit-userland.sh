#!/bin/sh
# Real-userland check for the installers' 32-bit refusal (issue #170).
#
# select_agent_binary refuses a 32-bit userland on a 64-bit kernel when
# `getconf LONG_BIT` prints exactly 32: 32-bit Raspberry Pi OS on a Pi 4 or 5
# boots a 64-bit kernel by default, so `uname -m` says aarch64 over an armhf
# userland that has no loader for the arm64 build. ci/test-signing.sh only
# ever fakes getconf. This runs the real function against the real getconf of
# an i386 glibc and an i386 musl userland, which run natively on an x86_64
# kernel (no emulation), and against their amd64 counterparts as controls: a
# false refusal there would block every install.
#
# Needs docker on an x86_64 host. Usage: sh ci/test-32bit-userland.sh

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The function under test and the helpers it calls, verbatim.
sed -n '/^print_success()/,/^}/p
        /^print_error()/,/^}/p
        /^detect_libc()/,/^}/p
        /^select_agent_binary()/,/^}/p' "$ROOT/fivenines_common.sh" > "$WORK/select.sh"

FAIL=0

# $1 image, $2 platform, $3 a line the run must print (fixed string), $4 the
# status select_agent_binary must return.
run_case() {
  # linux64 pins the 64-bit-kernel personality this check is about: the
  # runtime does not set a 32-bit one for linux/386 today, but if it did,
  # uname -m would say i686 and the i386 cases would be refused by the case
  # branch without ever reaching getconf. Debian ships it in util-linux,
  # Alpine as a busybox applet. The $ in the inline script is meant for the
  # container's shell.
  # shellcheck disable=SC2016
  out=$(docker run --rm --platform "$2" -v "$WORK/select.sh:/select.sh:ro" "$1" \
    linux64 sh -c '. /select.sh
           echo "uname -m: $(uname -m), getconf LONG_BIT: $(getconf LONG_BIT)"
           select_agent_binary
           echo "rc=$?"' 2>&1)
  printf '== %s (%s)\n%s\n' "$1" "$2" "$out"
  if printf '%s\n' "$out" | grep -qF "$3" && printf '%s\n' "$out" | grep -qx "rc=$4"; then
    echo "  ok   $1"
  else
    echo "  FAIL $1: expected '$3' and rc=$4"
    FAIL=$((FAIL + 1))
  fi
  echo ""
}

run_case i386/debian:bookworm-slim linux/386 "32-bit userland on a 64-bit x86_64 kernel" 1
run_case i386/alpine:3.21 linux/386 "32-bit userland on a 64-bit x86_64 kernel" 1
run_case debian:bookworm-slim linux/amd64 "(fivenines-agent-linux-amd64)" 0
run_case alpine:3.21 linux/amd64 "(fivenines-agent-alpine-amd64)" 0

echo "FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
