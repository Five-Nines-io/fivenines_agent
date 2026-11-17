#!/bin/sh

# Fivenines Agent Setup Script
# Works on standard Linux systems (systemd), OpenRC (Alpine), and UNRAID
#
# Usage:
#   sudo bash fivenines_setup.sh TOKEN [--with-sudoers]
#   sudo bash fivenines_setup.sh --from-user [USER] [--with-sudoers]
#
#   --from-user [USER]  Move USER's user-level installation (fivenines_setup_user.sh;
#                       default: the user who ran sudo) to this system installation.
#                       The system agent keeps its token, machine id and state, so the
#                       dashboard keeps the same host; the user-level agent is stopped
#                       and its files removed. If it was installed with
#                       FIVENINES_INSTALL_DIR / FIVENINES_CONFIG_DIR, pass the same
#                       values. Not on UNRAID.
#   --with-sudoers      Write /etc/sudoers.d/fivenines: the README's sudoers rules for
#                       the monitoring tools installed here (smartctl, mdadm,
#                       fail2ban-client, wg), each checked with visudo first.
#
# Environment variables:
#   FIVENINES_AGENT_URL    - Custom download URL for the agent tarball (e.g., pre-release
#                            builds). Unverified unless FIVENINES_AGENT_SHA256 is also set.
#   FIVENINES_AGENT_SHA256 - Expected SHA-256 of the tarball. Overrides the published
#                            SHA256SUMS; the only way to verify a custom URL.
#   FIVENINES_SKIP_VERIFY  - Set to 1 to install WITHOUT verifying the tarball. Unsupported.
#   FIVENINES_ALLOW_UNSIGNED - Set to 1 to install on a host with no openssl, with
#                            checksum-only verification. Without it, a missing openssl
#                            aborts the install (the signature cannot be checked).
#   FIVENINES_REQUIRE_SIGNATURE - Set to 1 to abort even when this installer embeds no
#                            public key at all (the key-rotation escape hatch). A
#                            signature that cannot be checked is already fatal.
#
# Example with custom build:
#   FIVENINES_AGENT_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/download/feature-branch-abc1234/fivenines-agent-linux-amd64.tar.gz" bash fivenines_setup.sh YOUR_TOKEN

# Mirror URLs (R2 is IPv6-compatible, GitHub is fallback). Both serve
# published release assets, which the signed SHA256SUMS covers. The raw
# main-branch URL that used to serve the service unit, the OpenRC script and
# the UNRAID boot script is deliberately gone: nothing signs a moving branch,
# so those files could never be verified while they came from there (#154).
R2_BASE_URL="https://releases.fivenines.io/latest"
GITHUB_RELEASES_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/latest/download"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo ""
    printf '%b\n' "${BLUE}===============================================================${NC}"
    printf '%b\n' "${BLUE}  Fivenines Agent - System Installation${NC}"
    printf '%b\n' "${BLUE}===============================================================${NC}"
    echo ""
}

print_success() {
    printf '%b\n' "${GREEN}[+]${NC} $1"
}

print_warning() {
    printf '%b\n' "${YELLOW}[!]${NC} $1"
}

print_error() {
    printf '%b\n' "${RED}[-]${NC} $1"
}

download_with_fallback() {
  filename="$1"
  output="$2"
  r2_url="${R2_BASE_URL}/${filename}"
  github_url="$3"

  print_warning "Downloading ${filename}..."

  # Record which mirror served the file: the checksum has to be read from
  # that same mirror (see download_sums).
  DOWNLOAD_SOURCE=""

  # Try R2 first (IPv6 compatible)
  # Use -T (BusyBox-compatible) instead of --connect-timeout (GNU wget only)
  if wget -T 5 -q "$r2_url" -O "$output" 2>/dev/null; then
    DOWNLOAD_SOURCE="r2"
    print_success "Downloaded from releases.fivenines.io"
    return 0
  fi

  # Fallback to GitHub
  print_warning "R2 mirror unavailable, trying GitHub..."
  if wget -T 5 -q "$github_url" -O "$output" 2>/dev/null; then
    DOWNLOAD_SOURCE="github"
    print_success "Downloaded from GitHub"
    return 0
  fi

  return 1
}

exit_with_contact() {
  print_error "$1"
  # --from-user stopped the user-level agent: put it back rather than leave
  # the host unmonitored (see rollback_user_takeover).
  if [ "${TAKEOVER_ROLLBACK:-0}" = "1" ]; then
    rollback_user_takeover
  fi
  echo ""
  echo "For assistance, contact: sebastien@fivenines.io"
  exit 1
}

# Everything downloaded before it has been verified lands in a private
# directory. /tmp is world-writable and these files are written as root under
# predictable names, so a local user who pre-creates one as a symlink turns a
# download into an arbitrary root-owned overwrite. mktemp -d hands back a
# fresh 0700 directory that nobody else can have staged in advance.
make_work_dir() {
    dir=$(mktemp -d 2>/dev/null) || return 1
    [ -d "$dir" ] || return 1
    chmod 700 "$dir" 2>/dev/null || true
    printf '%s' "$dir"
}

# Portable SHA-256 of a file. Prints the lowercase hex digest on stdout, or
# nothing at all when the host has no digest tool. sha256sum covers coreutils
# and BusyBox (so every distro in the support matrix); shasum and openssl are
# fallbacks for stripped-down images.
compute_sha256() {
    file="$1"

    if command -v sha256sum > /dev/null 2>&1; then
        sha256sum "$file" 2>/dev/null | cut -d' ' -f1
    elif command -v shasum > /dev/null 2>&1; then
        shasum -a 256 "$file" 2>/dev/null | cut -d' ' -f1
    elif command -v openssl > /dev/null 2>&1; then
        # "SHA256(file)= <hex>" on every OpenSSL back to 1.0.2 (CentOS 7).
        openssl dgst -sha256 "$file" 2>/dev/null | sed 's/^.*= *//'
    fi
}

# Look up one file's expected digest in a sha256sum-format SHA256SUMS file.
# The name is matched exactly, and against the whole field: a substring or
# suffix match would let the arm64 line answer a request for the amd64
# tarball. "*name" is the binary-mode spelling of the same entry. Prints
# nothing and returns non-zero when the file is not listed.
sha256_from_sums() {
    sums_file="$1"
    wanted="$2"

    awk -v want="$wanted" '
        $2 == want || $2 == "*" want { print $1; found = 1; exit }
        END { exit !found }
    ' "$sums_file" 2>/dev/null
}

# Compare a downloaded file against an expected digest. Returns 0 only on a
# proven match: a host with no digest tool returns non-zero exactly like a
# mismatch does, because "could not check it" and "checked it and it is
# wrong" must not install different amounts of code.
verify_sha256() {
    file="$1"
    expected=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')
    label="$3"

    actual=$(compute_sha256 "$file" | tr '[:upper:]' '[:lower:]')

    if [ -z "$actual" ]; then
        print_error "Cannot verify ${label}: this host has no sha256sum, shasum or openssl."
        print_error "Install coreutils and re-run, or see the README to override deliberately."
        return 1
    fi

    if [ "$actual" != "$expected" ]; then
        print_error "Checksum mismatch for ${label}"
        print_error "  expected: ${expected}"
        print_error "  actual:   ${actual}"
        return 1
    fi

    print_success "Verified ${label} (sha256 ${actual})"
    return 0
}

# Public key the release signature is checked against. ECDSA P-256 with
# SHA-256 rather than Ed25519: OpenSSL 1.0.2 on CentOS 7 cannot verify
# Ed25519, and CentOS 7 is in the support matrix.
#
# The matching PRIVATE key lives only in the RELEASE_SIGNING_KEY secret of
# the `release` GitHub environment, which only v* tag builds can read - never
# in the release bucket - which is what makes this worth anything: a mirror
# that rewrites SHA256SUMS cannot re-sign it.
#
# ROTATION IS A BREAKING CHANGE. Every installed agent carries the key below
# verbatim, so a release signed with a different key is REJECTED by every
# host until it picks up a new installer. To rotate: publish the installer
# carrying the new key first, let the fleet take it, and only then switch
# RELEASE_SIGNING_KEY. Emptying this block is the escape hatch - it drops
# back to checksum-only verification, loudly, rather than failing closed.
#
#   openssl ecparam -name prime256v1 -genkey -noout -out fivenines-release.key
#   openssl ec -in fivenines-release.key -pubout
#
# The key must be identical here and in all four install scripts;
# ci/build-scripts.sh --check fails if they drift, because a key pasted into
# three scripts out of four leaves the fourth verifying nothing. CI also
# refuses to sign a release whose key does not match this block.
release_signing_pubkey() {
    cat <<'PUBKEY'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYEeNw0yIcXeLpQifrLGT7iU02K9R
36O9k+TrWYiVYF2xyCrykF3qFkwOOAl+gbFmi6c/9oFsMFcuinr8p9UJtw==
-----END PUBLIC KEY-----
PUBKEY
}

# Verify the detached signature over SHA256SUMS. Four outcomes, and the
# difference between the last three is the whole point:
#   0 - verified against the embedded public key
#   1 - a signature was expected and did NOT verify. Always fatal.
#   2 - no key is embedded in this script at all. That is the documented
#       rotation escape hatch (see release_signing_pubkey), not a property of
#       the host, so it degrades to checksum-only with a warning.
#   3 - a key IS embedded but this host has no openssl to check it with.
#       Fatal by default since 1.18.1: "the signature is good" and "I could
#       not look at the signature" must not install the same bytes, and a
#       host with no openssl is exactly the host an attacker would prefer to
#       be talking to. FIVENINES_ALLOW_UNSIGNED=1 is the documented opt-out.
verify_sums_signature() {
    sums_file="$1"
    sig_file="$2"

    pubkey=$(release_signing_pubkey)
    if [ -z "$pubkey" ]; then
        return 2
    fi

    if ! command -v openssl > /dev/null 2>&1; then
        print_warning "No openssl on this host: the release signature cannot be checked."
        return 3
    fi

    if [ ! -s "$sig_file" ]; then
        print_error "SHA256SUMS.sig is missing or empty: this release should carry a signature."
        return 1
    fi

    pubkey_file="${sums_file}.pub"
    printf '%s\n' "$pubkey" > "$pubkey_file"

    if openssl dgst -sha256 -verify "$pubkey_file" -signature "$sig_file" "$sums_file" > /dev/null 2>&1; then
        rm -f "$pubkey_file"
        print_success "Release signature verified against the embedded public key."
        return 0
    fi

    rm -f "$pubkey_file"
    print_error "Release signature does NOT verify against the embedded public key."
    print_error "Someone may be serving you artifacts that fivenines.io did not publish."
    return 1
}

# SHA256SUMS and its signature have to come from the SAME mirror that served
# the tarball. The two mirrors are written by different steps of the release
# job, so during a release they can briefly hold different versions, and a
# manifest read from the other mirror would reject a perfectly good download.
download_release_file() {
  remote="$1"
  output="$2"

  case "${DOWNLOAD_SOURCE:-}" in
    r2) url="${R2_BASE_URL}/${remote}" ;;
    github) url="${GITHUB_RELEASES_URL}/${remote}" ;;
    *) return 1 ;;
  esac

  wget -T 10 -q "$url" -O "$output" 2>/dev/null
}

# NOTE: the functions below call download_release_file and
# download_with_fallback, which are deliberately NOT shared: the system
# scripts fetch with wget directly while the user scripts go through
# download_file (wget or curl). Each script defines its own, just above its
# copy of these functions.
# Check one downloaded artifact against the signed manifest the same mirror
# publishes. Shared by the agent tarball and by the startup definitions the
# system installers drop into place as root, so both get the same proof.
#
# The two layers do different jobs. The digest alone proves the bytes arrived
# intact and are the ones that mirror published - a truncated download, a
# half-finished mirror sync, a swapped asset. It cannot catch an attacker who
# owns the mirror, because they would rewrite SHA256SUMS too. The signature
# is what closes that: the signing key lives in a GitHub environment secret,
# not in the bucket, so a manifest the attacker rewrote will not verify
# (issue #143).
verify_from_manifest() {
    file="$1"
    asset_name="$2"

    sums_path="${file}.SHA256SUMS"
    sig_path="${sums_path}.sig"
    rm -f "$sums_path" "$sig_path"

    if ! download_release_file "SHA256SUMS" "$sums_path"; then
        print_error "Could not download SHA256SUMS from the mirror that served ${asset_name}."
        rm -f "$sums_path" "$sig_path"
        return 1
    fi

    # Fetch the signature unconditionally. Whether its absence is fatal is
    # verify_sums_signature's decision, not the download's - otherwise an
    # attacker could downgrade the check by dropping one request.
    download_release_file "SHA256SUMS.sig" "$sig_path" || true

    sig_status=0
    verify_sums_signature "$sums_path" "$sig_path" || sig_status=$?

    if [ "$sig_status" -eq 1 ]; then
        rm -f "$sums_path" "$sig_path"
        return 1
    fi

    if [ "$sig_status" -eq 3 ]; then
        # No openssl here, so the signature cannot be checked at all. Fail
        # closed: a digest read out of a manifest nobody authenticated only
        # proves the mirror agrees with itself, which is free for whoever
        # owns the mirror.
        if [ "${FIVENINES_ALLOW_UNSIGNED:-}" != "1" ]; then
            print_error "Cannot verify the release signature: this host has no openssl."
            print_error "Install it and re-run:"
            print_error "  apk add openssl  |  apt-get install -y openssl  |  yum install -y openssl"
            print_error "To install anyway, with checksum-only verification, re-run with"
            print_error "FIVENINES_ALLOW_UNSIGNED=1 (see the README)."
            rm -f "$sums_path" "$sig_path"
            return 1
        fi
        print_warning "FIVENINES_ALLOW_UNSIGNED=1 - the release signature was NOT checked."
    elif [ "$sig_status" -eq 2 ]; then
        # No key embedded in this script: the rotation escape hatch.
        if [ "${FIVENINES_REQUIRE_SIGNATURE:-}" = "1" ]; then
            print_error "FIVENINES_REQUIRE_SIGNATURE=1, but this installer embeds no public key."
            rm -f "$sums_path" "$sig_path"
            return 1
        fi
        print_warning "Release signature not checked - falling back to the published checksum."
    fi

    expected_sha256=$(sha256_from_sums "$sums_path" "$asset_name" || true)
    rm -f "$sums_path" "$sig_path"

    if [ -z "$expected_sha256" ]; then
        print_error "${asset_name} is not listed in the published SHA256SUMS."
        return 1
    fi

    verify_sha256 "$file" "$expected_sha256" "$asset_name"
}

# Can this host verify a release AT ALL? Called before anything is stopped,
# downloaded or replaced.
#
# Since 1.18.1 a signature that cannot be checked is fatal, and "no openssl"
# is a property of the host, not of the download: on a minimal image (busybox
# has no openssl applet, and `openssl` is a separate apk/apt package) EVERY
# update would fail. The update scripts stop the agent before they verify
# anything, so without this preflight that deterministic failure lands after
# the stop and leaves the host unmonitored. Fail while the agent is still
# running, and say exactly what to install.
# The scope argument is optional by design: the system scripts pass one, the
# user scripts have no startup definition to verify and pass none.
# shellcheck disable=SC2120
verification_preflight() {
    # "$1" is "with-startup-files" when the caller also installs a startup
    # definition (the two SYSTEM scripts), or runs one of the release's
    # scripts as root (fivenines_setup_user.sh --from-system and its
    # fivenines_uninstall.sh). Those always go through the signed
    # manifest -- install_verified_release_file ignores FIVENINES_AGENT_SHA256,
    # which pins the TARBALL only -- so a pinned digest does not exempt them,
    # or the preflight would pass and the refusal would land after the agent
    # was stopped and the binary replaced.
    pf_scope="${1:-}"

    # FIVENINES_TEST_MODE skips ALL service management, so a test-mode run
    # installs no startup definition however it was called -- and demanding
    # openssl for files it will never fetch turns the release test matrix red
    # on any image without the CLI (ci/test-distro.sh installs python3, wget
    # and shadow, and drives both system installers with a pinned digest).
    # This grants nothing: test mode already skips service setup entirely, and
    # anyone who can set it can already set FIVENINES_SKIP_VERIFY.
    if [ "${FIVENINES_TEST_MODE:-}" = "1" ]; then
        pf_scope=""
    fi

    if [ "${FIVENINES_SKIP_VERIFY:-}" = "1" ] || [ "${FIVENINES_ALLOW_UNSIGNED:-}" = "1" ]; then
        return 0
    fi
    if [ -n "${FIVENINES_AGENT_SHA256:-}" ] && [ "$pf_scope" != "with-startup-files" ]; then
        return 0  # operator-pinned digest, and nothing else needs a manifest
    fi
    if [ -z "$(release_signing_pubkey)" ]; then
        return 0  # no key embedded: checksum-only, openssl not required
    fi
    if command -v openssl > /dev/null 2>&1; then
        return 0
    fi

    print_error "This host has no openssl, so the release signature cannot be checked."
    print_error "Install it and re-run:"
    print_error "  apk add openssl  |  apt-get install -y openssl  |  yum install -y openssl"
    print_error "To proceed anyway, with checksum-only verification, re-run with"
    print_error "FIVENINES_ALLOW_UNSIGNED=1 (see the README)."
    return 1
}

# Check an agent tarball before it is unpacked. The expected digest comes from
# FIVENINES_AGENT_SHA256 when the operator pinned one, otherwise from the
# signed SHA256SUMS the same mirror publishes next to the tarball. A non-zero
# return means the tarball must not be installed.
verify_agent_tarball() {
    tarball="$1"
    asset_name="$2"

    if [ "${FIVENINES_SKIP_VERIFY:-}" = "1" ]; then
        print_warning "FIVENINES_SKIP_VERIFY=1 - installing an UNVERIFIED agent tarball."
        return 0
    fi

    if [ -n "${FIVENINES_AGENT_SHA256:-}" ]; then
        # An out-of-band digest from the operator: there is no manifest in
        # play, so there is nothing for the signature to cover.
        if verify_sha256 "$tarball" "$FIVENINES_AGENT_SHA256" "$asset_name"; then
            return 0
        fi
        return 1
    fi

    if [ -z "${DOWNLOAD_SOURCE:-}" ]; then
        # No mirror served this file: a custom FIVENINES_AGENT_URL, or a
        # tarball pre-placed by the CI test harness. There is no published
        # digest to check it against, so say so plainly rather than letting
        # silence imply it was checked.
        print_warning "UNVERIFIED agent tarball: this source publishes no checksum."
        print_warning "Pass FIVENINES_AGENT_SHA256=<sha256> to verify a custom build."
        return 0
    fi

    verify_from_manifest "$tarball" "$asset_name"
}

# Download one of the release's startup definitions - the systemd unit, the
# OpenRC init script, the UNRAID boot script - and put it in place ONLY if it
# verifies against the signed manifest.
#
# Until 1.18.1 these three were fetched straight from the mirror (and, on the
# GitHub fallback, from the main branch, which no manifest covers at all) and
# written directly to their final path. A compromised mirror therefore could
# not touch the agent binary, which was verified, but could still hand every
# installing host an ExecStart of its choosing - running as root, at every
# boot, until someone noticed. The startup definition is the more valuable of
# the two targets, not the lesser one (issue #154).
#
# Staged in the private work dir; whatever is already on disk is replaced only
# after the downloaded file verifies, so a failed check leaves a working
# install exactly as it was.
install_verified_release_file() {
    asset_name="$1"
    dest="$2"
    mode="$3"

    staged="${WORK_DIR}/${asset_name}"
    rm -f "$staged"

    download_with_fallback "$asset_name" "$staged" "${GITHUB_RELEASES_URL}/${asset_name}" || return 1

    if [ "${FIVENINES_SKIP_VERIFY:-}" = "1" ]; then
        print_warning "FIVENINES_SKIP_VERIFY=1 - installing an UNVERIFIED ${asset_name}."
    elif [ -z "${DOWNLOAD_SOURCE:-}" ]; then
        # Defensive: download_with_fallback sets DOWNLOAD_SOURCE on every path
        # that returns 0, so this is unreachable today. It stays because the
        # alternative to refusing is installing a root-run file nothing
        # checked, and that must never be the default when the seam changes.
        print_error "${asset_name} came from no known mirror, so nothing can verify it."
        rm -f "$staged"
        return 1
    elif ! verify_from_manifest "$staged" "$asset_name"; then
        rm -f "$staged"
        return 1
    fi

    # The destination directory is never created here: every supported target
    # (/etc/systemd/system, /etc/init.d, the UNRAID flash config dir) already
    # exists by the time this runs, and creating one would mean guessing that
    # an init system is present on a host where it is not.
    dest_dir=$(dirname "$dest")
    if [ ! -d "$dest_dir" ]; then
        print_error "${dest_dir} does not exist: not installing ${asset_name}."
        rm -f "$staged"
        return 1
    fi

    # Reached once the file verified, or once FIVENINES_SKIP_VERIFY=1 waived
    # the check.
    #
    # Land it through a sibling temp file INSIDE the destination directory,
    # not with a straight mv from the work dir. The work dir is under /tmp,
    # which on most systemd distros is a tmpfs while /etc is on the root
    # filesystem, so that mv is cross-device: open(dest, O_TRUNC) + copy +
    # unlink. A crash, OOM kill or power cut mid-copy leaves a TRUNCATED unit
    # or init script that the following daemon-reload would load. Copying to
    # ${dest}.fivenines-new first and renaming within the same filesystem
    # makes the replace atomic, and lets the mode and the SELinux label be
    # set before anything is visible at the real path.
    staging_dest="${dest}.fivenines-new"
    rm -f "$staging_dest"
    if ! cp "$staged" "$staging_dest"; then
        rm -f "$staged" "$staging_dest"
        return 1
    fi
    rm -f "$staged"

    # Best-effort, and deliberately not the function's exit status: UNRAID's
    # /boot is vfat, which has no POSIX modes at all (the mount options decide
    # them), so a failed chmod there must not turn a verified, correctly
    # installed boot script into a failed install.
    if ! chmod "$mode" "$staging_dest" 2>/dev/null; then
        print_warning "Could not set mode ${mode} on ${dest} (filesystem may not support it)."
    fi

    # Restore the SELinux label BEFORE the rename, so the file is never
    # visible at its real path with the wrong type. This is load-bearing, not
    # decoration: the previous code let wget CREATE the file inside its
    # destination directory, so it inherited the right type. A file copied out
    # of a /tmp work dir keeps the tmp label, and systemd running as init_t
    # cannot read a user_tmp_t unit -- the agent would fail to start on every
    # SELinux-enforcing RHEL-family host.
    if command -v restorecon > /dev/null 2>&1; then
        restorecon -v "$staging_dest" > /dev/null 2>&1 || true
    fi

    if ! mv "$staging_dest" "$dest"; then
        rm -f "$staging_dest"
        return 1
    fi
    return 0
}

# --with-sudoers (fivenines_setup.sh, fivenines_update.sh): the README's "Full
# Monitoring" sudoers rules, written for the monitoring tools this host has.
#
# Owned by root and writable by nobody else? find prints the path only when
# every test holds. A symlink's own mode is always 0777: root_only_chain
# follows links instead of asking this about them.
root_only_path() {
    [ -n "$(find "$1" -prune -user 0 ! -perm -020 ! -perm -002 2>/dev/null)" ]
}

# Can only root change what PATH resolves to? Every component from PATH up to
# /, and through each symbolic link met on the way (a root-owned link, then
# its target, the same way), is root's and writable by no one else. A link
# anywhere in the chain -- /usr/bin/wg -> /etc/alternatives/wg -> ... -- is
# itself replaceable by whoever can write to the directory holding it, so
# resolving the path first (readlink -f) would skip exactly those directories.
# Each link is followed in a subshell (sh has no local variables), at most 40
# deep, the kernel's own limit. The walk up ends at / or //, which POSIX lets
# dirname return for a path that starts with two slashes, and after 4096
# steps whatever happens.
root_only_chain() {
    if [ "${2:-0}" -gt 40 ]; then
        return 1
    fi
    chain_path="$1"
    chain_steps=0
    while :; do
        chain_steps=$((chain_steps + 1))
        if [ "$chain_steps" -gt 4096 ]; then
            return 1
        fi
        if [ -L "$chain_path" ]; then
            if [ -z "$(find "$chain_path" -prune -user 0 2>/dev/null)" ]; then
                return 1
            fi
            chain_target=$(readlink "$chain_path") || return 1
            case "$chain_target" in
                /*) ;;
                *)
                    chain_dir=$(dirname "$chain_path")
                    chain_target="${chain_dir%/}/${chain_target}"
                    ;;
            esac
            ( root_only_chain "$chain_target" $((${2:-0} + 1)) ) || return 1
        elif ! root_only_path "$chain_path"; then
            return 1
        fi
        case "$chain_path" in
            / | //) return 0 ;;
        esac
        chain_path=$(dirname "$chain_path")
    done
}

# The path a rule for TOOL names, or nothing and a non-zero status when TOOL is
# not installed, or when anyone but root could change what that path runs
# (root_only_chain): a rule there would hand root to whoever can. Looked up in
# sudo's usual secure_path, in its order, rather than in the caller's PATH (su
# without - keeps a PATH with no sbin). Warnings go to stderr: the path is
# this function's output.
sudoers_tool_path() {
    tool_path=""
    for tool_dir in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
        if [ -f "${tool_dir}/$1" ] && [ -x "${tool_dir}/$1" ]; then
            tool_path="${tool_dir}/$1"
            break
        fi
    done
    if [ -z "$tool_path" ]; then
        return 1
    fi
    if ! root_only_chain "$tool_path"; then
        print_warning "No sudoers rule for ${tool_path}: a user other than root can change what it runs." >&2
        return 1
    fi
    printf '%s' "$tool_path"
}

# Writes /etc/sudoers.d/fivenines. Each rule is written only if this host's
# visudo accepts it ON ITS OWN, so a rule one sudo does not understand (an old
# sudo, sudo-rs) costs that rule, never a file that breaks sudo for everyone.
# A file at that path whose first line is not the marker was written by the
# operator and is never touched; fivenines_uninstall.sh removes only a file
# that starts with the marker. Returns non-zero when nothing was written: the
# caller says so and carries on, since the agent runs without these rules.
write_sudoers_rules() {
    sudoers_file="/etc/sudoers.d/fivenines"
    sudoers_marker="# Managed by the fivenines agent installer (--with-sudoers)"

    if ! command -v visudo > /dev/null 2>&1; then
        print_warning "--with-sudoers: sudo is not installed here (no visudo), so no rule was written."
        return 1
    fi
    if [ ! -d /etc/sudoers.d ]; then
        print_warning "--with-sudoers: /etc/sudoers.d does not exist, so no rule was written."
        return 1
    fi
    if [ -e "$sudoers_file" ] || [ -L "$sudoers_file" ]; then
        if ! head -n 1 "$sudoers_file" 2>/dev/null | grep -qxF "$sudoers_marker"; then
            print_warning "--with-sudoers: ${sudoers_file} was not written by this installer, so it was left as it is."
            return 1
        fi
    fi

    sudoers_staged="${WORK_DIR}/sudoers"
    sudoers_one="${WORK_DIR}/sudoers.rule"
    rm -f "$sudoers_staged" "$sudoers_one"
    if ! printf '%s\n%s\n' "$sudoers_marker" \
        "# The monitoring commands of the fivenines agent (README, Full Monitoring)." \
        > "$sudoers_staged"; then
        return 1
    fi
    sudoers_rules=0
    for sudoers_tool in smartctl mdadm fail2ban-client wg; do
        sudoers_path=$(sudoers_tool_path "$sudoers_tool") || continue
        # Each tool that can run code or change the host given other
        # arguments is held to the argv the agent runs. sudo matches a
        # wildcard across argument boundaries, so a pattern that must not
        # reach a further argument has no '*'.
        case "$sudoers_tool" in
            mdadm)
                # raid_storage.py: --version, and --detail on /dev/<name> for
                # each md line of /proc/mdstat. "--detail *" would also match
                # "--detail /dev/md0 --stop /dev/md1" (misc mode takes an
                # action per device), and a bare rule allows --monitor
                # --program, which runs a command as root. An array the kernel
                # names otherwise (CREATE names=yes, md_d0, md1000) gets its
                # own exact entry: without one the agent's --detail would be
                # refused on every collection, and on Debian and Ubuntu sudo
                # mails root each refusal. One created later needs this run
                # again.
                sudoers_rule="fivenines ALL=(ALL) NOPASSWD: ${sudoers_path} --version, ${sudoers_path} --detail /dev/md[0-9], ${sudoers_path} --detail /dev/md[0-9][0-9], ${sudoers_path} --detail /dev/md[0-9][0-9][0-9]"
                # One array name per line, never a space (awk prints the first
                # field), so the words are the names.
                # shellcheck disable=SC2013
                for sudoers_md in $(awk '/^md/ { print $1 }' /proc/mdstat 2>/dev/null); do
                    case "$sudoers_md" in
                        md[0-9] | md[0-9][0-9] | md[0-9][0-9][0-9]) ;;
                        # A dash and a dot need no escaping in a rule.
                        *[!A-Za-z0-9_.-]* | . | ..)
                            print_warning "No sudoers entry for /dev/${sudoers_md}: its name holds a character a rule cannot carry as is."
                            ;;
                        *) sudoers_rule="${sudoers_rule}, ${sudoers_path} --detail /dev/${sudoers_md}" ;;
                    esac
                done
                ;;
            fail2ban-client)
                # fail2ban.py: version, status, status JAIL. A bare rule allows
                # "set JAIL action ... actionban CMD", which runs CMD as root;
                # anything after status only reaches the read-only status.
                sudoers_rule="fivenines ALL=(ALL) NOPASSWD: ${sudoers_path} version, ${sudoers_path} status, ${sudoers_path} status *"
                ;;
            wg)
                # The exact argv wireguard.py runs, never wg alone, which would
                # let the agent reconfigure every tunnel. NOLOG_OUTPUT keeps
                # the keys the dump prints out of an I/O log.
                sudoers_rule="fivenines ALL=(root) NOPASSWD:NOLOG_OUTPUT: ${sudoers_path} show all dump"
                ;;
            *)
                # smartctl: the agent passes options and a device that vary by
                # drive, so the rule names none. It runs no command and writes
                # no file, but it can change a drive's settings (-s, --set,
                # -t): the README says so.
                sudoers_rule="fivenines ALL=(ALL) NOPASSWD: ${sudoers_path}"
                ;;
        esac
        rm -f "$sudoers_one"
        printf '%s\n' "$sudoers_rule" > "$sudoers_one" && chmod 440 "$sudoers_one"
        if visudo -cf "$sudoers_one" > /dev/null 2>&1; then
            printf '%s\n' "$sudoers_rule" >> "$sudoers_staged"
            sudoers_rules=$((sudoers_rules + 1))
            print_success "sudoers rule: ${sudoers_rule}"
        else
            print_warning "This host's visudo rejects '${sudoers_rule}': not written."
        fi
    done
    rm -f "$sudoers_one"

    if [ "$sudoers_rules" -eq 0 ]; then
        print_warning "--with-sudoers: none of smartctl, mdadm, fail2ban-client or wg is usable here, so no rule was written."
        rm -f "$sudoers_staged"
        return 1
    fi
    chmod 440 "$sudoers_staged"
    if ! visudo -cf "$sudoers_staged" > /dev/null 2>&1; then
        print_warning "--with-sudoers: visudo rejects the rules together, so none was written."
        rm -f "$sudoers_staged"
        return 1
    fi

    # Landed like install_verified_release_file lands a unit: through a
    # sibling in the destination directory, renamed into place. sudo skips
    # every name in /etc/sudoers.d that contains a dot, so it never reads the
    # sibling half-written, and a file created there gets the directory's
    # SELinux type (sudo cannot read one labelled as /tmp).
    sudoers_new="${sudoers_file}.fivenines-new"
    rm -f "$sudoers_new"
    if ! cp "$sudoers_staged" "$sudoers_new" || ! chown 0:0 "$sudoers_new" \
        || ! chmod 440 "$sudoers_new"; then
        rm -f "$sudoers_staged" "$sudoers_new"
        return 1
    fi
    rm -f "$sudoers_staged"
    if command -v restorecon > /dev/null 2>&1; then
        restorecon "$sudoers_new" > /dev/null 2>&1 || true
    fi
    if ! mv -f "$sudoers_new" "$sudoers_file"; then
        rm -f "$sudoers_new"
        return 1
    fi
    print_success "Wrote ${sudoers_file} (${sudoers_rules} rule(s))"
    if ! grep -Eq '^[[:space:]]*[#@]includedir[[:space:]]+/etc/sudoers\.d/?[[:space:]]*$' /etc/sudoers 2>/dev/null; then
        print_warning "/etc/sudoers has no includedir line for /etc/sudoers.d: sudo ignores ${sudoers_file} until it does."
    fi
    return 0
}

# An earlier README gave the fivenines account bare mdadm and fail2ban-client
# rules, which let it run code as root (mdadm --monitor --program,
# fail2ban-client set JAIL action ...). Said at every install and update while
# sudo still lists one; the operator's sudoers files are never edited.
warn_unpinned_sudoers_rules() {
    command -v sudo > /dev/null 2>&1 || return 0
    id fivenines > /dev/null 2>&1 || return 0
    # sudo -l -U lists each rule's commands after its tags, comma-separated:
    # a bare one is a path followed by a comma or the end of the line.
    unpinned_rules=$(sudo -n -l -U fivenines 2>/dev/null \
        | grep -oE '(: |, )/[^ ,]*/(mdadm|fail2ban-client)(,|[[:space:]]*$)' \
        | sed 's/^[:,] //; s/[,[:space:]]*$//' | sort -u | tr '\n' ' ')
    if [ -n "$unpinned_rules" ]; then
        print_warning "sudo lets the fivenines account run ${unpinned_rules}with any arguments (a rule from an earlier version of the README): that lets it run code as root. Replace it with the rules of the README's Full Monitoring section, which name the commands the agent runs, or remove it and re-run with --with-sudoers."
    fi
    return 0
}

detect_libc() {
    # Check ldd first - if it explicitly reports glibc or musl, trust that
    LDD_OUTPUT=$(ldd --version 2>&1 || true)
    if printf '%s' "$LDD_OUTPUT" | grep -qi glibc; then
        echo "glibc"
    elif printf '%s' "$LDD_OUTPUT" | grep -qi musl; then
        echo "musl"
    elif [ -f "/lib/ld-musl-x86_64.so.1" ] || [ -f "/lib/ld-musl-aarch64.so.1" ]; then
        echo "musl"
    else
        echo "glibc"
    fi
}

# Which published build runs on this host. Sets CURRENT_ARCH, LIBC_TYPE and
# BINARY_NAME, or says why there is none and returns non-zero.
#
# Only the architectures a release actually ships are mapped. The two system
# installers used to hand everything else the amd64 build, which verified
# against SHA256SUMS, installed, and then failed at exec with "Exec format
# error" on every restart (armv7l on 32-bit Raspberry Pi OS, i686, ppc64le,
# s390x, riscv64; issue #170). Every installer calls this before anything is
# downloaded, stopped or changed, so a refused host is left exactly as it was.
# amd64 and arm64 are deliberately not accepted: Linux always reports x86_64
# and aarch64, while amd64 and arm64 are what FreeBSD and Apple-silicon macOS
# report, and a Linux binary cannot run there either.
select_agent_binary() {
    CURRENT_ARCH=$(uname -m)
    LIBC_TYPE=$(detect_libc)
    BINARY_NAME=""
    case "$CURRENT_ARCH" in
        x86_64)
            agent_arch="amd64"
            ;;
        aarch64)
            agent_arch="arm64"
            ;;
        *)
            print_error "Unsupported architecture: $CURRENT_ARCH"
            print_error "Agent binaries are published for x86_64 and aarch64 (64-bit ARM) only."
            return 1
            ;;
    esac
    # uname -m names the KERNEL, not the userland the agent has to run in.
    # 32-bit Raspberry Pi OS on a Pi 4 or 5 boots a 64-bit kernel by default,
    # so it reports aarch64 and would be handed a build it has no loader for.
    # getconf LONG_BIT is the userland's word size. Only an explicit 32
    # refuses: a host with no getconf is not guessed at.
    if [ "$(getconf LONG_BIT 2>/dev/null)" = "32" ]; then
        print_error "Unsupported system: 32-bit userland on a 64-bit $CURRENT_ARCH kernel"
        print_error "Agent binaries are published for 64-bit x86_64 and aarch64 systems only."
        return 1
    fi
    if [ "$LIBC_TYPE" = "musl" ]; then
        BINARY_NAME="fivenines-agent-alpine-${agent_arch}"
    else
        BINARY_NAME="fivenines-agent-linux-${agent_arch}"
    fi
    print_success "Detected architecture: $CURRENT_ARCH, libc: $LIBC_TYPE ($BINARY_NAME)"
    # Explicit: the status is the verdict on the host, never whether that line
    # could be written (a closed or full stdout would otherwise refuse here).
    return 0
}

detect_system() {
  # Check if this is UNRAID
  if [ -f "/etc/unraid-version" ] || [ -d "/boot/config" ]; then
    echo "unraid"
    return
  fi

  # Check if OpenRC is available (Alpine Linux)
  if command -v rc-service >/dev/null 2>&1 && [ -d "/etc/init.d" ]; then
    echo "openrc"
    return
  fi

  # Check if systemd is available
  if command -v systemctl >/dev/null 2>&1 && [ -d "/etc/systemd/system" ]; then
    echo "systemd"
    return
  fi

  # Fallback - check for other init systems
  if [ -f "/sbin/init" ]; then
    init_system=$(readlink -f /sbin/init)
    case "$init_system" in
      *systemd*)
        echo "systemd"
        ;;
      *)
        echo "other"
        ;;
    esac
  else
    echo "unknown"
  fi
}

setup_selinux_contexts() {
  # Detect SELinux mode using getenforce (part of libselinux-utils, guaranteed
  # on every SELinux system). Falls back to sestatus if getenforce is missing.
  if command -v getenforce >/dev/null 2>&1; then
    selinux_mode=$(getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]')
  elif command -v sestatus >/dev/null 2>&1; then
    selinux_mode=$(sestatus 2>/dev/null | awk -F: '/^Current mode:/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print tolower($2)}')
  else
    print_success "SELinux is not installed on this system."
    return 0
  fi

  if [ -z "$selinux_mode" ]; then
    print_success "SELinux status: Disabled"
    return 0
  fi

  print_success "SELinux mode: $selinux_mode"

  if [ "$selinux_mode" = "disabled" ]; then
    return 0
  fi

  if [ "$selinux_mode" = "permissive" ]; then
    print_warning "SELinux is in Permissive mode. Applying default contexts for consistency."
    if command -v restorecon >/dev/null 2>&1; then
      restorecon -Rv "$INSTALL_DIR" /etc/fivenines_agent 2>/dev/null || true
    fi
    return 0
  fi

  # Enforcing mode: try to load policy module and apply file contexts
  if [ "$selinux_mode" != "enforcing" ]; then
    return 0
  fi

  print_warning "SELinux is Enforcing. Configuring contexts for fivenines agent..."

  if ! command -v semanage >/dev/null 2>&1 || ! command -v restorecon >/dev/null 2>&1; then
    print_warning "semanage or restorecon not found. Install policycoreutils-python-utils and run: restorecon -Rv $INSTALL_DIR /etc/fivenines_agent"
    return 0
  fi

  SELINUX_TMP="/tmp/fivenines_agent_selinux"
  mkdir -p "$SELINUX_TMP"

  # Look for policy files bundled with the agent (preferred: version-matched)
  SELINUX_SRC=""
  if [ -d "$AGENT_DIR/selinux" ]; then
    SELINUX_SRC="$AGENT_DIR/selinux"
  fi

  for f in fivenines_agent.te fivenines_agent.fc; do
    if [ -n "$SELINUX_SRC" ] && [ -f "$SELINUX_SRC/$f" ]; then
      cp "$SELINUX_SRC/$f" "$SELINUX_TMP/$f"
    else
      print_warning "SELinux policy file $f not found in agent bundle. SELinux policy not applied."
      print_warning "To run under Enforcing, add a policy module or set SELinux to Permissive."
      rm -rf "$SELINUX_TMP"
      return 0
    fi
  done

  # Copy optional modules if available (Docker, libvirt)
  for f in fivenines_agent_docker.te fivenines_agent_libvirt.te; do
    if [ -n "$SELINUX_SRC" ] && [ -f "$SELINUX_SRC/$f" ]; then
      cp "$SELINUX_SRC/$f" "$SELINUX_TMP/$f"
    fi
  done

  # Build and load module if selinux-policy-devel is available
  if [ -f /usr/share/selinux/devel/Makefile ]; then
    ( cd "$SELINUX_TMP" && make -f /usr/share/selinux/devel/Makefile clean 2>/dev/null; make -f /usr/share/selinux/devel/Makefile )
    if [ -f "$SELINUX_TMP/fivenines_agent.pp" ]; then
      # Remove any existing module from ALL priorities to avoid typeattributeset errors
      # (a stale copy at priority 400 will override the new one at 100 and fail)
      # NOTE: keep in sync with cleanup_selinux_contexts() in fivenines_uninstall.sh
      semodule -X 400 -r fivenines_agent 2>/dev/null || true
      semodule -X 100 -r fivenines_agent 2>/dev/null || true
      semodule -r fivenines_agent 2>/dev/null || true
      if semodule -i "$SELINUX_TMP/fivenines_agent.pp" -X 100 2>/dev/null; then
        print_success "SELinux policy module fivenines_agent loaded."
      else
        print_warning "Failed to load SELinux module. Run: semodule -r fivenines_agent; semodule -i fivenines_agent.pp -X 100"
      fi

      # Load optional Docker module if built and container-selinux types exist
      if [ -f "$SELINUX_TMP/fivenines_agent_docker.pp" ]; then
        semodule -r fivenines_agent_docker 2>/dev/null || true
        if semodule -i "$SELINUX_TMP/fivenines_agent_docker.pp" -X 100 2>/dev/null; then
          print_success "SELinux optional module fivenines_agent_docker loaded."
        else
          print_warning "Docker SELinux module not loaded (container-selinux may not be installed). Docker monitoring may hit denials."
        fi
      fi

      # Load optional libvirt module if built and libvirt types exist
      if [ -f "$SELINUX_TMP/fivenines_agent_libvirt.pp" ]; then
        semodule -r fivenines_agent_libvirt 2>/dev/null || true
        if semodule -i "$SELINUX_TMP/fivenines_agent_libvirt.pp" -X 100 2>/dev/null; then
          print_success "SELinux optional module fivenines_agent_libvirt loaded."
        else
          print_warning "Libvirt SELinux module not loaded (libvirt policy may not be installed). QEMU monitoring may hit denials."
        fi
      fi
    else
      print_warning "SELinux policy build failed. Install selinux-policy-devel and ensure refpolicy matches your distro."
    fi
  else
    print_warning "SELinux policy devel Makefile not found. Install selinux-policy-devel to build the module, or use a prebuilt .pp."
  fi

  # Apply file contexts: if module was loaded, .fc is in the policy and restorecon applies it
  if semanage fcontext -l 2>/dev/null | grep -q fivenines_agent_exec_t; then
    restorecon -Rv "$INSTALL_DIR" /etc/fivenines_agent 2>/dev/null || true
    if [ -f /var/log/fivenines-agent.log ]; then
      restorecon -v /var/log/fivenines-agent.log 2>/dev/null || true
    fi
    print_success "SELinux file contexts applied."
  else
    # Module not loaded: apply default contexts so the agent may still run
    restorecon -Rv "$INSTALL_DIR" /etc/fivenines_agent 2>/dev/null || true
    print_warning "SELinux policy module not loaded. Agent may hit denials under Enforcing. Install selinux-policy-devel and re-run setup, or setenforce 0."
  fi

  rm -rf "$SELINUX_TMP"
}

setup_systemd() {
  print_success "Detected systemd system - using systemd service"

  # Download the service file and verify it against the signed manifest
  # before it lands: the unit runs as root at every boot, so it gets the same
  # proof as the binary it starts (issue #154).
  install_verified_release_file "fivenines-agent.service" \
    "/etc/systemd/system/fivenines-agent.service" 644 \
    || exit_with_contact "Failed to install a verified systemd service file"

  # Fix the SELinux label on the freshly installed unit
  if command -v restorecon >/dev/null 2>&1; then
    restorecon -v /etc/systemd/system/fivenines-agent.service 2>/dev/null || true
  fi

  # Reload the service files to include the new fivenines-agent service
  systemctl daemon-reload

  # Enable fivenines-agent service on every reboot
  systemctl enable fivenines-agent.service

  # Start the fivenines-agent
  if ! systemctl start fivenines-agent; then
    exit_with_contact "Failed to start the fivenines-agent service. Check the system logs for more information."
  fi

  print_success "Systemd service installed and started successfully"
}

setup_unraid() {
  print_warning "Starting fivenines agent..."

  # Same rule as the systemd unit: this script is what /boot/config/go runs
  # as root on every boot, so it is verified before it is written (#154).
  install_verified_release_file "fivenines_script.sh" \
    "/boot/config/custom/fivenines_agent/fivenines_boot" 755 \
    || exit_with_contact "Failed to install a verified fivenines_script.sh"

  bash /boot/config/custom/fivenines_agent/fivenines_boot

  sleep 3

  if pgrep -f "fivenines_agent" > /dev/null; then
    print_success "Fivenines agent is running (PID: $(pgrep -f "fivenines_agent"))"
    if ! grep -q "fivenines_boot" /boot/config/go; then
      print_success "Adding fivenines agent to go startup"
      echo "# Start fivenines agent on boot" >> /boot/config/go
      echo "bash /boot/config/custom/fivenines_agent/fivenines_boot" >> /boot/config/go
    else
      print_success "Fivenines agent is already in go startup"
    fi
  else
    exit_with_contact "Failed to start fivenines agent. Check /var/log/fivenines-agent.log for details."
  fi
}

setup_openrc() {
  print_success "Detected OpenRC system - using OpenRC service"

  # Download the OpenRC init script, verified before it is written (#154)
  install_verified_release_file "fivenines-agent.openrc" \
    "/etc/init.d/fivenines-agent" 755 \
    || exit_with_contact "Failed to install a verified OpenRC init script"

  # Enable on boot
  rc-update add fivenines-agent default

  # Start the agent
  if ! rc-service fivenines-agent start; then
    exit_with_contact "Failed to start the fivenines-agent service. Check /var/log/fivenines-agent.log for details."
  fi

  print_success "OpenRC service installed and started successfully"
}

# ---------------------------------------------------------------------------
# --from-user: move a user-level installation (fivenines_setup_user.sh) to
# this system installation.
#
# The system agent takes over the user-level agent's identity -- its TOKEN
# (the per-host token it swapped the enrollment token for) and its MACHINE_ID
# -- and its state, so the dashboard keeps the same host instead of enrolling
# a second one. The user-level agent is stopped before the service starts (two
# agents with one identity would report as one host, twice), and its files are
# removed only once the service has started.
#
# Everything on the user's side is done AS THAT USER (as_user), never as root:
# their home is theirs to change, so a root read of their TOKEN, or a root rm
# of their files, would follow any symlink they put there.
# ---------------------------------------------------------------------------

# What the agent keeps in its config directory that the new installation
# carries over: its identity (TOKEN, MACHINE_ID), the capture nonce that keeps
# a capture command from firing twice, and the operator's journal allowlist
# (dropping it would WIDEN what the agent may read; it can only narrow what the
# server's list allows, so a user's copy grants nothing). ci/build-scripts.sh
# keeps this line equal to the one in fivenines_setup_user.sh.
#
# Not carried INTO the system installation, since the user wrote them and the
# system agent runs with more access than they have: .env (it is loaded into
# the agent's environment: API_URL alone would send the system agent, its
# journal access and its sudo rules, to a server of the user's choosing; it is
# left in place, and said), image_inventory_done (it would let them mark an
# image as scanned; it is only a cache, rebuilt by scanning each image once),
# and sudo_refusals (what sudo told another account).
STATE_FILES="TOKEN MACHINE_ID last_capture_id journal_units.allow"
# A state file is a few KB at most: anything bigger is not one.
STATE_FILE_MAX=16777216

# as_user SCRIPT [ARG...]: run SCRIPT with sh as the user being moved, with
# the ARGs as $1, $2... They are never pasted into SCRIPT, so a path is never
# parsed as shell code. SCRIPT can run the user's own stop.sh and start.sh, so
# it gets nothing of root's but PATH: no other variable of root's environment
# (env -i: a credential exported in root's shell would reach the user's code
# and the agent restarted), and no terminal (setsid, stdin from /dev/null,
# output through files in a root-only directory): with the admin's terminal,
# a process the user left behind could push keystrokes into root's shell
# (TIOCSTI) or read what the admin types next.
as_user() {
  as_user_script="$1"
  shift
  as_user_tmp=$(mktemp -d) || return 1
  as_user_rc=0
  env -i PATH="$PATH" setsid su -s /bin/sh -c "cd / && ${as_user_script}" "$FROM_USER_NAME" sh "$@" \
    < /dev/null > "$as_user_tmp/out" 2> "$as_user_tmp/err" || as_user_rc=$?
  cat "$as_user_tmp/out"
  cat "$as_user_tmp/err" >&2
  rm -rf "${as_user_tmp:?}"
  return "$as_user_rc"
}

resolve_takeover_user() {
  if [ -z "$FROM_USER_NAME" ]; then
    FROM_USER_NAME="${SUDO_USER:-}"
  fi
  if [ -z "$FROM_USER_NAME" ]; then
    exit_with_contact "Name the user whose installation to move: fivenines_setup.sh --from-user USER"
  fi
  case "$FROM_USER_NAME" in
    -*|*:*|*/*)
      exit_with_contact "Not a user name: $FROM_USER_NAME"
      ;;
  esac
  passwd_line=$(getent passwd "$FROM_USER_NAME" 2>/dev/null \
    || awk -F: -v name="$FROM_USER_NAME" '$1 == name' /etc/passwd 2>/dev/null)
  passwd_line=$(printf '%s\n' "$passwd_line" | head -n 1)
  FROM_USER_HOME=$(printf '%s' "$passwd_line" | cut -d: -f6)
  if [ -z "$FROM_USER_HOME" ]; then
    exit_with_contact "There is no user named $FROM_USER_NAME on this host."
  fi
  # getent also answers a uid; su is given the name.
  FROM_USER_NAME=$(printf '%s' "$passwd_line" | cut -d: -f1)
  # The variables, and defaults, fivenines_setup_user.sh installs with.
  USER_INSTALL_DIR="${FIVENINES_INSTALL_DIR:-$FROM_USER_HOME/.local/fivenines}"
  USER_CONFIG_DIR="${FIVENINES_CONFIG_DIR:-$FROM_USER_HOME/.config/fivenines_agent}"
}

# Before anything is installed, so a refusal leaves the host as it was.
preflight_user_takeover() {
  resolve_takeover_user
  if [ "$SYSTEM_TYPE" = "unraid" ]; then
    exit_with_contact "--from-user is not supported on UNRAID."
  fi
  # Its identity would be overwritten, and its host left with no agent.
  if [ -e /etc/fivenines_agent/TOKEN ]; then
    exit_with_contact "A system installation already exists (/etc/fivenines_agent/TOKEN). Remove it with fivenines_uninstall.sh first, or keep it and remove the user-level one with fivenines_uninstall_user.sh."
  fi
  # Any other state file there would be replaced by the user's, and deleted
  # if the move is undone.
  for state_file in $STATE_FILES; do
    if [ -e "/etc/fivenines_agent/$state_file" ] || [ -L "/etc/fivenines_agent/$state_file" ]; then
      exit_with_contact "/etc/fivenines_agent/$state_file exists, left by an earlier installation: the move would replace it with the one of $FROM_USER_NAME, and delete it if undone. Move it aside (or remove /etc/fivenines_agent, if no agent uses it) and re-run."
    fi
  done
  if ! command -v base64 > /dev/null 2>&1; then
    exit_with_contact "--from-user needs base64 (coreutils or busybox) to carry the agent's state over."
  fi
  if ! command -v setsid > /dev/null 2>&1; then
    exit_with_contact "--from-user needs setsid (util-linux or busybox), to run $FROM_USER_NAME's scripts away from this terminal."
  fi
  if ! as_user 'exit 0'; then
    exit_with_contact "Cannot run a command as $FROM_USER_NAME with su."
  fi
  # The installation's own start.sh is what ties the two directories
  # together. Without it (FIVENINES_INSTALL_DIR not passed again), the running
  # agent could not be found to be stopped, and would go on beside the
  # service with the same identity. The quoted $1 and $2 are as_user's
  # arguments, expanded by the user's shell.
  # shellcheck disable=SC2016
  if ! as_user 'test -f "$1/TOKEN" && test -s "$1/TOKEN" && test -f "$2/start.sh" \
      && grep -qxF "export CONFIG_DIR=\"$1\"" "$2/start.sh"' "$USER_CONFIG_DIR" "$USER_INSTALL_DIR"; then
    exit_with_contact "No user-level installation of $FROM_USER_NAME found in $USER_INSTALL_DIR with its config in $USER_CONFIG_DIR (a TOKEN, and a start.sh naming that config directory). If it was installed with FIVENINES_INSTALL_DIR or FIVENINES_CONFIG_DIR, pass the same values: sudo FIVENINES_INSTALL_DIR=... FIVENINES_CONFIG_DIR=... bash fivenines_setup.sh --from-user"
  fi
  print_success "Moving the user-level installation of $FROM_USER_NAME ($USER_INSTALL_DIR) to a system installation"
}

# A plain install by a user who already runs a user-level agent: both would
# run, as two hosts. Not refused (it may be deliberate), but said, with the
# way to move it instead.
hint_user_installation() {
  if [ -z "${SUDO_USER:-}" ]; then
    return 0
  fi
  hint_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
  if [ -n "$hint_home" ] && [ -f "$hint_home/.config/fivenines_agent/TOKEN" ]; then
    print_warning "$SUDO_USER has a user-level agent ($hint_home/.local/fivenines): it keeps running beside this one, as another host."
    print_warning "To move it to a system installation instead, keeping its host: sudo bash fivenines_setup.sh --from-user"
  fi
}

# The pgrep -f pattern for an agent run from INSTALL_DIR: anchored on the
# agent's own path (start.sh runs it by that path), so neither another user's
# agent nor a shell or a tail -f that merely names a file in that directory
# ever matches, with the regex characters a path may hold (/home/a+b) escaped.
agent_pattern() {
    printf '^%s/fivenines-agent-' "$(printf '%s' "$1" | sed 's/[][\.*^$+?(){}|]/\\&/g')"
}

# How a crontab line can name INSTALL_DIR's start.sh: the absolute path the
# installers print and, when INSTALL_DIR is under HOME, the ~/ form the README
# shows and its $HOME/ and ${HOME}/ forms. Sets START_SPELLING_1 to _4 (all
# four the absolute path when INSTALL_DIR is not under HOME).
start_spellings() {
    START_SPELLING_1="$1/start.sh"
    START_SPELLING_2="$START_SPELLING_1"
    START_SPELLING_3="$START_SPELLING_1"
    START_SPELLING_4="$START_SPELLING_1"
    start_rel="${1#"$2"/}"
    if [ -n "$2" ] && [ "$start_rel" != "$1" ]; then
        # The tilde and the dollar signs are the literal text of the line.
        # shellcheck disable=SC2088
        START_SPELLING_2="~/$start_rel/start.sh"
        START_SPELLING_3="\$HOME/$start_rel/start.sh"
        START_SPELLING_4="\${HOME}/$start_rel/start.sh"
    fi
}

# stop.sh first (it kills the PID it recorded), then any agent still running
# from that installation, as the user, so no other user's process can be hit.
# The pattern is anchored: start.sh runs the agent by its path, so its command
# line STARTS with it, while a shell or a tail -f that merely names a file in
# that directory does not.
stop_user_agent() {
  print_warning "Stopping the user-level agent of $FROM_USER_NAME..."
  # shellcheck disable=SC2016
  as_user '
    pattern="$2"
    # Never an empty or unanchored pattern: pkill -f "" signals every process
    # of the user.
    case "$pattern" in
      "^/"?*) ;;
      *) exit 1 ;;
    esac
    if [ -x "$1/stop.sh" ]; then
      "$1/stop.sh" > /dev/null 2>&1 || true
    fi
    command -v pgrep > /dev/null 2>&1 || exit 0
    tries=0
    while pgrep -f "$pattern" > /dev/null 2>&1; do
      tries=$((tries + 1))
      if [ "$tries" -gt 10 ]; then
        pkill -KILL -f "$pattern" > /dev/null 2>&1 || true
        sleep 1
        break
      fi
      pkill -f "$pattern" > /dev/null 2>&1 || true
      sleep 1
    done
    ! pgrep -f "$pattern" > /dev/null 2>&1' "$USER_INSTALL_DIR" "$(agent_pattern "$USER_INSTALL_DIR")"
}

# su and sudo can print to stdout before the command does (a PAM session
# module: RHEL's postlogin runs pam_lastlog with showfailed, which reports
# failed logins), so a state file crosses over base64-encoded between two
# marker lines, and only what lies between them is kept. base64's alphabet has
# no dash, so no encoded line can read as a marker. fivenines_setup_user.sh
# carries the same function, for sudo (ci/build-scripts.sh keeps them equal).
decode_state() {
    if ! grep -qx 'fivenines-state-end' "$1"; then
        return 1
    fi
    sed -n '/^fivenines-state-begin$/,/^fivenines-state-end$/p' "$1" | sed '1d;$d' | base64 -d > "$2"
}

# After the user-level agent stopped (it may have just swapped its token):
# read each state file as the user, then install it for the fivenines user.
# A file that exists but is not a regular file, or cannot be read, stops the
# move rather than being dropped: a journal allowlist left behind would let
# the agent read every unit's journal.
import_user_state() {
  state_stash="${WORK_DIR}/user_state"
  mkdir "$state_stash" || return 1
  for state_file in $STATE_FILES; do
    # shellcheck disable=SC2016
    as_user '
      if [ ! -e "$1" ] && [ ! -L "$1" ]; then exit 3; fi
      if [ -L "$1" ] || [ ! -f "$1" ] || [ ! -r "$1" ]; then exit 4; fi
      echo "fivenines-state-begin"
      head -c "$2" -- "$1" | base64
      echo "fivenines-state-end"' "$USER_CONFIG_DIR/$state_file" "$((STATE_FILE_MAX + 1))" \
      > "$state_stash/$state_file.b64"
    state_rc=$?
    if [ "$state_rc" -eq 0 ] \
      && ! decode_state "$state_stash/$state_file.b64" "$state_stash/$state_file"; then
      state_rc=5
    fi
    rm -f "${state_stash:?}/${state_file:?}.b64"
    case "$state_rc" in
      0) ;;
      3)
        continue
        ;;
      4)
        print_error "$USER_CONFIG_DIR/$state_file is not a regular file $FROM_USER_NAME can read: fix or remove it, then re-run."
        return 1
        ;;
      *)
        print_error "Could not read $USER_CONFIG_DIR/$state_file as $FROM_USER_NAME."
        return 1
        ;;
    esac
    if [ "$(wc -c < "$state_stash/$state_file")" -gt "$STATE_FILE_MAX" ]; then
      print_error "$USER_CONFIG_DIR/$state_file is larger than any agent state file."
      return 1
    fi
  done
  if [ ! -s "$state_stash/TOKEN" ]; then
    print_error "$USER_CONFIG_DIR/TOKEN is empty."
    return 1
  fi
  # Root writes these by name, and /etc/fivenines_agent belongs to the
  # fivenines account: while it does, the directory is root's alone, so no
  # process of that account can put a link where root writes, or swap a file
  # between its cp and its chown.
  if ! chown 0:0 /etc/fivenines_agent || ! chmod 700 /etc/fivenines_agent; then
    print_error "Could not make /etc/fivenines_agent root-only while its state is written."
    return 1
  fi
  state_rc=0
  for state_file in $STATE_FILES; do
    if [ ! -f "$state_stash/$state_file" ]; then
      continue
    fi
    state_dest="/etc/fivenines_agent/$state_file"
    # The operator's allowlist: the agent reads it and never writes it (the
    # README has it written with sudo tee).
    if [ "$state_file" = "journal_units.allow" ]; then
      state_owner="0:0"
      state_mode=644
    else
      state_owner="fivenines:fivenines"
      state_mode=600
    fi
    # Recorded before it is written, so a rollback takes back a file whose
    # chown or chmod failed, or that a signal cut short.
    IMPORTED_STATE_FILES="$IMPORTED_STATE_FILES $state_file"
    rm -f "${state_dest:?}"
    if ! (umask 077 && cp "$state_stash/$state_file" "$state_dest") \
      || ! chown "$state_owner" "$state_dest" || ! chmod "$state_mode" "$state_dest"; then
      print_error "Could not install $state_dest."
      state_rc=1
      break
    fi
    print_success "Carried over $state_file"
  done
  if ! chown fivenines:fivenines /etc/fivenines_agent || ! chmod 750 /etc/fivenines_agent; then
    print_error "Could not give /etc/fivenines_agent back to the fivenines account."
    state_rc=1
  fi
  if [ "$state_rc" -ne 0 ]; then
    return 1
  fi
  if command -v restorecon > /dev/null 2>&1; then
    restorecon -R /etc/fivenines_agent > /dev/null 2>&1 || true
  fi
  # shellcheck disable=SC2016
  if as_user 'test -e "$1/.env"' "$USER_CONFIG_DIR"; then
    print_warning "$USER_CONFIG_DIR/.env was not carried over: it would configure the system agent from a file $FROM_USER_NAME controls. It stays in place; review it, and copy what you need to /etc/fivenines_agent/.env."
  fi
}

# A move that failed after the user-level agent was stopped: remove the
# identity copied for the service (so it cannot start later as a second copy
# of that host) -- only what import_user_state installed --, stop and disable
# the service, and start the user-level agent again, whose files were not
# touched. A second signal is ignored: cut halfway, the rollback could leave
# the service enabled with the identity and the user-level agent stopped.
rollback_user_takeover() {
  trap '' INT TERM HUP
  TAKEOVER_ROLLBACK=0
  print_warning "Putting the user-level agent of $FROM_USER_NAME back..."
  for state_file in $IMPORTED_STATE_FILES; do
    rm -f "/etc/fivenines_agent/${state_file:?}"
  done
  if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
    if [ "$SYSTEM_TYPE" = "openrc" ]; then
      rc-service fivenines-agent stop > /dev/null 2>&1 || true
      rc-update del fivenines-agent default > /dev/null 2>&1 || true
    else
      systemctl stop fivenines-agent.service > /dev/null 2>&1 || true
      systemctl disable fivenines-agent.service > /dev/null 2>&1 || true
    fi
  fi
  # shellcheck disable=SC2016
  if [ "${FIVENINES_TEST_MODE:-}" != "1" ] \
    && as_user '"$1/start.sh"' "$USER_INSTALL_DIR" > /dev/null 2>&1; then
    print_warning "The user-level agent of $FROM_USER_NAME runs again, unchanged."
  else
    print_warning "Start the user-level agent again as $FROM_USER_NAME: $USER_INSTALL_DIR/start.sh"
  fi
}

# Once the service has started. Only the files fivenines_setup_user.sh
# creates are removed, and each directory only once nothing else is left in
# it, so a directory FIVENINES_INSTALL_DIR pointed at keeps everything else.
# Failures are warnings: the system agent already runs.
remove_user_installation() {
  # The @reboot line, however it names start.sh (the README writes ~/...).
  start_spellings "$USER_INSTALL_DIR" "$FROM_USER_HOME"
  # shellcheck disable=SC2016
  if ! as_user '
    command -v crontab > /dev/null 2>&1 || exit 0
    entries=$(crontab -l 2>/dev/null) || exit 0
    printf "%s\n" "$entries" | grep -qF -e "$1" -e "$2" -e "$3" -e "$4" || exit 0
    printf "%s\n" "$entries" | grep -vF -e "$1" -e "$2" -e "$3" -e "$4" | crontab -' \
    "$START_SPELLING_1" "$START_SPELLING_2" "$START_SPELLING_3" "$START_SPELLING_4"; then
    print_warning "Could not remove $USER_INSTALL_DIR/start.sh from the crontab of $FROM_USER_NAME: remove it with crontab -e."
  fi
  # shellcheck disable=SC2016
  if as_user '
    rc=0
    for name in start.sh stop.sh status.sh logs.sh refresh.sh agent.pid agent.log; do
      rm -f -- "${1:?}/${name:?}" || rc=1
    done
    for agent_dir in "$1"/fivenines-agent-*; do
      if [ -d "$agent_dir" ] && [ ! -L "$agent_dir" ]; then
        rm -rf -- "${agent_dir:?}" || rc=1
      fi
    done
    for name in $3 image_inventory_done sudo_refusals; do
      rm -f -- "${2:?}/${name:?}" || rc=1
    done
    for dir in "$1" "$2"; do
      rmdir -- "$dir" 2> /dev/null || true
      if [ -e "$dir" ]; then
        echo "Kept $dir: it holds other files."
      fi
    done
    exit "$rc"' "$USER_INSTALL_DIR" "$USER_CONFIG_DIR" "$STATE_FILES"; then
    print_success "Removed the user-level installation of $FROM_USER_NAME"
  else
    print_warning "Some files of the user-level installation of $FROM_USER_NAME could not be removed (see above): remove them as $FROM_USER_NAME. The system agent runs; do not start the user-level one."
  fi
}

# Test mode: skip network calls and service management for CI testing
if [ "${FIVENINES_TEST_MODE:-}" = "1" ]; then
  print_warning "WARNING: Test mode enabled - skipping network checks and service management"
fi

# Main execution starts here
print_banner

usage() {
  echo "Usage: sudo bash fivenines_setup.sh TOKEN [--with-sudoers]"
  echo "       sudo bash fivenines_setup.sh --from-user [USER] [--with-sudoers]"
  exit 1
}

# Only these exact words are options: anything else is the token (or, with
# --from-user, the user name), since a token may itself start with a dash.
TOKEN=""
FROM_USER=0
FROM_USER_NAME=""
WITH_SUDOERS=0
# Never inherited from the environment: set only once the user-level agent
# was stopped, and it makes exit_with_contact undo the move.
TAKEOVER_ROLLBACK=0
IMPORTED_STATE_FILES=""
POSITIONAL_COUNT=0
for arg in "$@"; do
  case "$arg" in
    --from-user) FROM_USER=1 ;;
    --with-sudoers) WITH_SUDOERS=1 ;;
    *)
      POSITIONAL_COUNT=$((POSITIONAL_COUNT + 1))
      if [ "$POSITIONAL_COUNT" -eq 1 ]; then
        TOKEN="$arg"
      fi
      ;;
  esac
done
if [ "$FROM_USER" = "1" ]; then
  # The token comes from the user-level installation; the one word allowed
  # is the user's name.
  if [ "$POSITIONAL_COUNT" -gt 1 ]; then
    usage
  fi
  FROM_USER_NAME="$TOKEN"
  TOKEN=""
elif [ -z "$TOKEN" ]; then
  usage
fi

# Check if running as root (use `id -u` for BusyBox/ash compatibility)
if [ "$(id -u)" -ne 0 ]; then
  exit_with_contact "This script must be run as root"
fi

# Refuse a host no release has a binary for before the user, the token or the
# install directory is created (issue #170).
select_agent_binary || exit_with_contact "No agent binary runs on this host -- nothing was installed."

# Refuse early if this host cannot verify a release at all, rather than after
# the download (issue #154).
verification_preflight "with-startup-files" || exit_with_contact "Cannot verify a release on this host -- nothing was installed."

# Detect system type
SYSTEM_TYPE=$(detect_system)
print_success "Detected system type: $SYSTEM_TYPE"

if [ "$FROM_USER" = "1" ]; then
  preflight_user_takeover
else
  hint_user_installation
fi

# SELinux contexts are configured after agent extraction (see setup_selinux_contexts)

# Create a system user for the agent first
if ! id -u fivenines >/dev/null 2>&1; then
  print_success "Creating system user fivenines"
  if [ "$SYSTEM_TYPE" = "unraid" ]; then
    useradd --system --user-group fivenines --shell /bin/false --create-home
  elif [ "$SYSTEM_TYPE" = "openrc" ]; then
    addgroup -S fivenines 2>/dev/null || true
    adduser -S -G fivenines -s /sbin/nologin -h /opt/fivenines fivenines 2>/dev/null || true
  else
    useradd --system --user-group --key USERGROUPS_ENAB=yes fivenines --shell /bin/false --create-home -b /opt/
  fi
fi

# CloudLinux: add fivenines to clsupergid group for proper permissions
if [ -f "/etc/cloudlinux-release" ]; then
  print_success "CloudLinux detected"
  if getent group clsupergid >/dev/null 2>&1; then
    print_success "Adding fivenines user to clsupergid group"
    usermod -a -G clsupergid fivenines
  fi
fi

mkdir -p /etc/fivenines_agent
# The agent runs as the fivenines user and must be able to CREATE files in
# this directory (MACHINE_ID and other persisted state), not just rewrite the
# TOKEN file. Without ownership the machine id can never persist, and every
# bulk (enrollment-token) install enrolls a duplicate host because the server
# has no dedup key. 750 rather than 755: the directory holds TOKEN and
# MACHINE_ID, and nothing outside root/fivenines needs to read it.
chown fivenines:fivenines /etc/fivenines_agent
chmod 750 /etc/fivenines_agent
# Save the client token in appropriate location. With --from-user the token
# is the user-level agent's, carried over once that agent has stopped
# (import_user_state).
if [ "$FROM_USER" = "1" ]; then
  :
elif [ "$SYSTEM_TYPE" = "unraid" ]; then
  mkdir -p /boot/config/custom/fivenines_agent
  printf '%s' "$TOKEN" | tee /boot/config/custom/fivenines_agent/TOKEN > /dev/null
  chown fivenines:fivenines /boot/config/custom/fivenines_agent/TOKEN
  chmod 600 /boot/config/custom/fivenines_agent/TOKEN
else
  # Use standard location for other systems
  printf '%s' "$TOKEN" | tee /etc/fivenines_agent/TOKEN > /dev/null
  chown fivenines:fivenines /etc/fivenines_agent/TOKEN
  chmod 600 /etc/fivenines_agent/TOKEN
fi

# Set install directory based on system type (BINARY_NAME was chosen by
# select_agent_binary, above)
if [ "$SYSTEM_TYPE" = "unraid" ]; then
  INSTALL_DIR="/boot/config/custom/fivenines_agent"
else
  INSTALL_DIR="/opt/fivenines"
fi

# Ensure install directory exists
mkdir -p "$INSTALL_DIR"

TARBALL_NAME="${BINARY_NAME}.tar.gz"

# The CI harness pre-places a tarball at the old, predictable path; it is
# copied into the private work directory rather than used in place, so the
# verified-then-extracted file is one nothing else can swap underneath us.
PREPLACED_TARBALL="/tmp/${TARBALL_NAME}"
WORK_DIR=$(make_work_dir) || exit_with_contact "Failed to create a private temporary directory"
trap 'rm -rf "$WORK_DIR"' EXIT
TARBALL_PATH="${WORK_DIR}/${TARBALL_NAME}"
AGENT_DIR="${INSTALL_DIR}/${BINARY_NAME}"
AGENT_EXECUTABLE="${AGENT_DIR}/${BINARY_NAME}"

# Only download_with_fallback sets this; an empty value means the tarball did
# not come from a mirror that publishes a checksum.
DOWNLOAD_SOURCE=""

if [ "${FIVENINES_TEST_MODE:-}" = "1" ] && [ -f "$PREPLACED_TARBALL" ]; then
  print_warning "Using pre-placed tarball at $PREPLACED_TARBALL (test mode)"
  cp "$PREPLACED_TARBALL" "$TARBALL_PATH" || exit_with_contact "Failed to stage the pre-placed tarball"
elif [ -n "${FIVENINES_AGENT_URL:-}" ]; then
  print_warning "Using custom agent URL: $FIVENINES_AGENT_URL"
  wget -T 10 -q "$FIVENINES_AGENT_URL" -O "$TARBALL_PATH" || exit_with_contact "Failed to download from custom URL"
  print_success "Downloaded from custom URL"
else
  download_with_fallback "$TARBALL_NAME" "$TARBALL_PATH" "${GITHUB_RELEASES_URL}/${TARBALL_NAME}" || exit_with_contact "Failed to download agent"
fi

# Verify before anything is unpacked as root, and before the previous
# installation is removed: a rejected tarball has to leave a working agent
# exactly where it was.
if ! verify_agent_tarball "$TARBALL_PATH" "$TARBALL_NAME"; then
  rm -f "$TARBALL_PATH"
  exit_with_contact "Refusing to install an unverified agent tarball. No agent binary was unpacked; any existing installation is untouched."
fi

# Remove old installation if it exists
if [ -d "$AGENT_DIR" ]; then
  print_warning "Removing previous installation..."
  rm -rf "$AGENT_DIR"
fi

# Extract the tarball
print_warning "Extracting agent to $INSTALL_DIR..."
tar -xzf "$TARBALL_PATH" -C "$INSTALL_DIR" || exit_with_contact "Failed to extract agent"

# Clean up the tarball
rm -f "$TARBALL_PATH"

# Verify extraction was successful
if [ ! -f "$AGENT_EXECUTABLE" ]; then
  exit_with_contact "Agent executable not found after extraction at $AGENT_EXECUTABLE"
fi

# Handle different systems for file permissions and binary location
if [ "$SYSTEM_TYPE" = "unraid" ]; then
  # For UNRAID, create a symlink in /usr/local/bin for easy access
  chmod -R 755 "$AGENT_DIR"
  ln -sf "$AGENT_EXECUTABLE" /usr/local/bin/fivenines_agent
else
  # Create a symlink at a fixed path for the systemd service
  ln -sf "$AGENT_EXECUTABLE" "${INSTALL_DIR}/fivenines_agent"

  chown -R fivenines:fivenines "$INSTALL_DIR"
  chmod -R 755 "$AGENT_DIR"

  # Restore SELinux label on the symlink (belt-and-suspenders with bulk restorecon)
  if command -v restorecon >/dev/null 2>&1; then
    restorecon -v "${INSTALL_DIR}/fivenines_agent" 2>/dev/null || true
  fi
fi

print_success "Agent installed successfully at $AGENT_DIR"

# Configure SELinux contexts now that files are in place (skip in test mode)
if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
  setup_selinux_contexts
else
  print_warning "Skipping SELinux setup (test mode)"
fi

# Test connectivity (skip in test mode)
if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
  echo "Testing connectivity..."
  for host in asia.fivenines.io eu.fivenines.io us.fivenines.io api.fivenines.io; do
    if ping -c 1 -W 5 "$host" >/dev/null 2>&1; then
      print_success "Connected to $host"
    else
      exit_with_contact "Ping to $host failed or timed out. Check your network connection."
    fi
  done
  echo ""
else
  print_warning "Skipping connectivity test (test mode)"
fi

# --from-user: the user-level agent stops only now, once everything that can
# fail on its own (download, checks, extraction, connectivity) has passed, and
# its state is read after it stopped. From here a failure puts it back
# (exit_with_contact -> rollback_user_takeover).
if [ "$FROM_USER" = "1" ]; then
  # Not interrupted halfway (a few seconds at most): stopped, the agent would
  # stay stopped, the move not yet armed to put it back.
  trap '' INT TERM HUP
  if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
    stop_user_agent || exit_with_contact "Could not stop the user-level agent of $FROM_USER_NAME, so nothing was moved. Stop it ($USER_INSTALL_DIR/stop.sh, as $FROM_USER_NAME) and re-run."
  else
    print_warning "Skipping the user-level agent stop (test mode)"
  fi
  TAKEOVER_ROLLBACK=1
  # From here an interrupted move is a failed one: put the user-level agent back.
  trap 'exit_with_contact "Interrupted."' INT TERM HUP
  import_user_state || exit_with_contact "Could not carry the state of $FROM_USER_NAME's agent over."
fi

# Before the service starts, so the agent's first capability probe sees them.
SUDOERS_SKIPPED=0
if [ "$WITH_SUDOERS" = "1" ]; then
  write_sudoers_rules || SUDOERS_SKIPPED=1
fi
warn_unpinned_sudoers_rules

# Setup based on system type (skip service management in test mode)
if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
  case "$SYSTEM_TYPE" in
    "unraid")
      setup_unraid "$TOKEN"
      ;;
    "openrc")
      setup_openrc
      ;;
    "systemd")
      setup_systemd
      ;;
    *)
      exit_with_contact "Unsupported system type: $SYSTEM_TYPE. This script supports systemd, OpenRC, and UNRAID systems."
      ;;
  esac
else
  print_warning "Skipping service setup (test mode)"
fi

if [ "$FROM_USER" = "1" ]; then
  TAKEOVER_ROLLBACK=0
  trap - INT TERM HUP
  remove_user_installation
fi

# Final output
echo ""
printf '%b\n' "${BLUE}===============================================================${NC}"
printf '%b\n' "${BLUE}  Installation Complete!${NC}"
printf '%b\n' "${BLUE}===============================================================${NC}"
echo ""

if [ "$FROM_USER" = "1" ]; then
  echo "The user-level agent of $FROM_USER_NAME now runs as this system installation,"
  echo "with the same token and machine id: the dashboard keeps the same host."
  echo ""
fi
if [ "$SUDOERS_SKIPPED" = "1" ]; then
  print_warning "No sudoers rule was written (see above). The README's Full Monitoring section lists them."
  echo ""
fi

if [ "$SYSTEM_TYPE" = "unraid" ]; then
  echo "The agent is now running and will automatically start when your UNRAID server boots."
  echo ""
  echo "Management options:"
  echo "  Settings -> User Scripts -> fivenines_agent"
  echo "  Log file: /var/log/fivenines-agent.log"
elif [ "$SYSTEM_TYPE" = "openrc" ]; then
  echo "The agent is now running as an OpenRC service and will start automatically on boot."
  echo ""
  echo "Management commands:"
  echo "  rc-service fivenines-agent status   - Check status"
  echo "  tail -f /var/log/fivenines-agent.log - View logs"
  echo "  rc-service fivenines-agent stop/start - Stop/start"
else
  echo "The agent is now running as a systemd service and will start automatically on boot."
  echo ""
  echo "Management commands:"
  echo "  systemctl status fivenines-agent    - Check status"
  echo "  journalctl -u fivenines-agent -f    - View logs"
  echo "  systemctl stop/start fivenines-agent - Stop/start"
fi

echo ""
echo "Happy monitoring!"

# Remove the setup script
rm -f "$0" 2>/dev/null || true
