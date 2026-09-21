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
SHARED_FUNCTIONS="detect_libc make_work_dir compute_sha256 sha256_from_sums verify_sha256 \
release_signing_pubkey verify_sums_signature verification_preflight \
verify_from_manifest verify_agent_tarball"

# Only the two SYSTEM installers place the startup definitions (systemd unit,
# OpenRC init script, UNRAID boot script), so only they carry the helper that
# verifies one before it lands. Checked in its own list rather than added to
# the one above, which would report it "MISSING" from the user scripts that
# have no business installing a service at all.
SYSTEM_FUNCTIONS="install_verified_release_file"

ALL_SCRIPTS="$SCRIPT_DIR/fivenines_setup.sh \
$SCRIPT_DIR/fivenines_update.sh \
$SCRIPT_DIR/fivenines_setup_user.sh \
$SCRIPT_DIR/fivenines_update_user.sh"

SYSTEM_SCRIPTS="$SCRIPT_DIR/fivenines_setup.sh \
$SCRIPT_DIR/fivenines_update.sh"

ERRORS=0

check_function_in() {
    func="$1"
    shift

    CANONICAL=$(sed -n "/^${func}()/,/^}/p" "$COMMON")

    if [ -z "$CANONICAL" ]; then
        echo "ERROR: ${func}() not found in fivenines_common.sh"
        ERRORS=$((ERRORS + 1))
        return
    fi

    for script in "$@"; do
        if [ ! -f "$script" ]; then
            # Never silent: a typo in the hardcoded lists below would
            # otherwise check nothing and still print "All shared functions
            # are in sync", and these lists name the two scripts that install
            # a root-run ExecStart.
            echo "ERROR: ${script} not found (check the script lists)"
            ERRORS=$((ERRORS + 1))
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
}

for func in $SHARED_FUNCTIONS; do
    # The script lists are deliberately word-split into separate arguments.
    # shellcheck disable=SC2086
    check_function_in "$func" $ALL_SCRIPTS
done

for func in $SYSTEM_FUNCTIONS; do
    # The script lists are deliberately word-split into separate arguments.
    # shellcheck disable=SC2086
    check_function_in "$func" $SYSTEM_SCRIPTS
done

# Functions the verification chain DEPENDS on but which cannot be canonical:
# download_with_fallback and download_release_file fetch with wget in the
# system scripts and through download_file (wget or curl) in the user scripts.
# They set and consume DOWNLOAD_SOURCE, which decides whether a root-installed
# startup definition is verified or refused, so drift inside a pair is still a
# security regression. Compare each pair against itself.
PAIR_FUNCTIONS="download_with_fallback download_release_file"

check_function_pair() {
    func="$1"
    a="$2"
    b="$3"

    A_COPY=$(sed -n "/^${func}()/,/^}/p" "$a")
    B_COPY=$(sed -n "/^${func}()/,/^}/p" "$b")

    if [ -z "$A_COPY" ] || [ -z "$B_COPY" ]; then
        echo "MISSING: ${func}() in $(basename "$a") or $(basename "$b")"
        ERRORS=$((ERRORS + 1))
    elif [ "$A_COPY" != "$B_COPY" ]; then
        echo "WARNING: ${func}() differs between $(basename "$a") and $(basename "$b")"
        ERRORS=$((ERRORS + 1))
    else
        echo "OK: ${func}() matches across $(basename "$a") / $(basename "$b")"
    fi
}

for func in $PAIR_FUNCTIONS; do
    check_function_pair "$func" \
        "$SCRIPT_DIR/fivenines_setup.sh" "$SCRIPT_DIR/fivenines_update.sh"
    check_function_pair "$func" \
        "$SCRIPT_DIR/fivenines_setup_user.sh" "$SCRIPT_DIR/fivenines_update_user.sh"
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
