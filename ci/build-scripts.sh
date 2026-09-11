#!/bin/sh
# Verify that shared shell functions are consistent across install scripts.
# fivenines_common.sh is the source of truth for shared functions.
#
# This script checks that key functions (detect_libc, the SHA-256 verification
# helpers, etc.) in each install script match the canonical versions in
# fivenines_common.sh.
#
# Usage: sh ci/build-scripts.sh [--check]
#   --check: Exit with error if functions are out of sync (CI mode)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
COMMON="$SCRIPT_DIR/fivenines_common.sh"
CHECK_MODE=false

if [ "${1:-}" = "--check" ]; then
    CHECK_MODE=true
fi

if [ ! -f "$COMMON" ]; then
    echo "ERROR: fivenines_common.sh not found at $COMMON"
    exit 1
fi

# Functions that must be byte-identical in every install script. The checksum
# and signature helpers are on this list deliberately: they are what stands
# between a tampered tarball and a root-level extract, so a copy that quietly
# drifts in one script is a security regression, not a style nit.
# release_signing_pubkey is here for the same reason - a public key pasted
# into three scripts out of four leaves the fourth verifying nothing.
SHARED_FUNCTIONS="detect_libc compute_sha256 sha256_from_sums verify_sha256 \
release_signing_pubkey verify_sums_signature verify_agent_tarball"

ERRORS=0

for func in $SHARED_FUNCTIONS; do
    CANONICAL=$(sed -n "/^${func}()/,/^}/p" "$COMMON")

    if [ -z "$CANONICAL" ]; then
        echo "ERROR: ${func}() not found in fivenines_common.sh"
        ERRORS=$((ERRORS + 1))
        continue
    fi

    for script in \
        "$SCRIPT_DIR/fivenines_setup.sh" \
        "$SCRIPT_DIR/fivenines_update.sh" \
        "$SCRIPT_DIR/fivenines_setup_user.sh" \
        "$SCRIPT_DIR/fivenines_update_user.sh"; do

        if [ ! -f "$script" ]; then
            continue
        fi

        COPY=$(sed -n "/^${func}()/,/^}/p" "$script")

        if [ -z "$COPY" ]; then
            echo "MISSING: ${func}() in $(basename "$script")"
            ERRORS=$((ERRORS + 1))
        elif [ "$CANONICAL" != "$COPY" ]; then
            echo "WARNING: ${func}() in $(basename "$script") differs from fivenines_common.sh"
            ERRORS=$((ERRORS + 1))
        else
            echo "OK: ${func}() in $(basename "$script")"
        fi
    done
done

if [ "$ERRORS" -gt 0 ]; then
    echo ""
    echo "$ERRORS function(s) out of sync with fivenines_common.sh"
    if [ "$CHECK_MODE" = true ]; then
        exit 1
    fi
else
    echo ""
    echo "All shared functions are in sync."
fi
