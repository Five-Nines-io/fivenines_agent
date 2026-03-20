#!/bin/sh
# Verify that shared shell functions are consistent across install scripts.
# fivenines_common.sh is the source of truth for shared functions.
#
# This script checks that key functions (detect_libc, detect_system, etc.)
# in each install script match the canonical versions in fivenines_common.sh.
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

# Extract the canonical detect_libc function from common.sh
CANONICAL_DETECT_LIBC=$(sed -n '/^detect_libc()/,/^}/p' "$COMMON")

ERRORS=0

# Check each script that contains detect_libc
for script in \
    "$SCRIPT_DIR/fivenines_setup.sh" \
    "$SCRIPT_DIR/fivenines_update.sh" \
    "$SCRIPT_DIR/fivenines_setup_user.sh" \
    "$SCRIPT_DIR/fivenines_update_user.sh"; do

    if [ ! -f "$script" ]; then
        continue
    fi

    SCRIPT_DETECT_LIBC=$(sed -n '/^detect_libc()/,/^}/p' "$script")

    if [ "$CANONICAL_DETECT_LIBC" != "$SCRIPT_DETECT_LIBC" ]; then
        echo "WARNING: detect_libc() in $(basename "$script") differs from fivenines_common.sh"
        ERRORS=$((ERRORS + 1))
    else
        echo "OK: detect_libc() in $(basename "$script")"
    fi
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
