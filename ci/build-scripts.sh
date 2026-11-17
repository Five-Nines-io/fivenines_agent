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
# select_agent_binary is the one uname -m -> artifact mapping: separate copies
# are how the system scripts came to hand every unknown architecture the amd64
# build while the user scripts refused it (issue #170).
SHARED_FUNCTIONS="detect_libc select_agent_binary make_work_dir compute_sha256 \
sha256_from_sums verify_sha256 release_signing_pubkey verify_sums_signature \
verification_preflight verify_from_manifest verify_agent_tarball"

# Only the two SYSTEM installers place the startup definitions (systemd unit,
# OpenRC init script, UNRAID boot script), so only they carry the helper that
# verifies one before it lands. Checked in its own list rather than added to
# the one above, which would report it "MISSING" from the user scripts that
# have no business installing a service at all. The --with-sudoers helpers
# are system-only for the same reason: they write a root-read sudoers file.
SYSTEM_FUNCTIONS="install_verified_release_file root_only_path root_only_chain sudoers_tool_path \
write_sudoers_rules"

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

# How a state file crosses su (--from-user) and sudo (--from-system): one
# decoder, so a fix to it cannot reach one direction only.
check_function_pair decode_state \
    "$SCRIPT_DIR/fivenines_setup.sh" "$SCRIPT_DIR/fivenines_setup_user.sh"

# How every script finds a user-level agent (agent_pattern: anchored on its
# path, so nothing else is signalled), writes the scripts that find it
# (write_control_scripts, rewritten by the update), and finds the crontab
# line that starts it (start_spellings). fivenines_setup_user.sh holds the
# reference copy of each.
for script in fivenines_setup.sh fivenines_update_user.sh fivenines_uninstall_user.sh; do
    check_function_pair agent_pattern \
        "$SCRIPT_DIR/fivenines_setup_user.sh" "$SCRIPT_DIR/$script"
done
for script in fivenines_setup.sh fivenines_uninstall_user.sh; do
    check_function_pair start_spellings \
        "$SCRIPT_DIR/fivenines_setup_user.sh" "$SCRIPT_DIR/$script"
done
check_function_pair write_control_scripts \
    "$SCRIPT_DIR/fivenines_setup_user.sh" "$SCRIPT_DIR/fivenines_update_user.sh"

# Constants two scripts must agree on, each a whole line. STATE_FILES and
# STATE_FILE_MAX: what fivenines_setup.sh --from-user and
# fivenines_setup_user.sh --from-system carry from one installation to the
# other -- a file one direction drops (the journal allowlist) widens what the
# agent may read. The sudoers marker: fivenines_uninstall.sh removes
# /etc/sudoers.d/fivenines only when its first line is the one
# write_sudoers_rules wrote.
check_line_pair() {
    label="$1"
    a_line="$2"
    b_line="$3"
    where="$4"

    if [ -z "$a_line" ] || [ -z "$b_line" ]; then
        echo "MISSING: ${label} in ${where}"
        ERRORS=$((ERRORS + 1))
    elif [ "$a_line" != "$b_line" ]; then
        echo "WARNING: ${label} differs between ${where}"
        ERRORS=$((ERRORS + 1))
    else
        echo "OK: ${label} matches across ${where}"
    fi
}

for const in STATE_FILES STATE_FILE_MAX; do
    check_line_pair "$const" \
        "$(grep "^${const}=" "$SCRIPT_DIR/fivenines_setup.sh")" \
        "$(grep "^${const}=" "$SCRIPT_DIR/fivenines_setup_user.sh")" \
        "fivenines_setup.sh / fivenines_setup_user.sh"
done

check_line_pair "the sudoers marker" \
    "$(sed -n 's/^    sudoers_marker="\(.*\)"$/\1/p' "$COMMON")" \
    "$(sed -n 's/^SUDOERS_MARKER="\(.*\)"$/\1/p' "$SCRIPT_DIR/fivenines_uninstall.sh")" \
    "fivenines_common.sh / fivenines_uninstall.sh"

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
