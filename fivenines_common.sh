#!/bin/sh
# Fivenines Agent - Shared Shell Functions
# This file is the source of truth for functions shared across install scripts.
# It is inlined into each script at build time by ci/build-scripts.sh.
# Do NOT distribute this file separately - install scripts must be self-contained.

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_success() {
    printf '%b\n' "${GREEN}[+]${NC} $1"
}

print_warning() {
    printf '%b\n' "${YELLOW}[!]${NC} $1"
}

print_error() {
    printf '%b\n' "${RED}[-]${NC} $1"
}

exit_with_error() {
    print_error "$1"
    echo ""
    echo "For assistance, contact: sebastien@fivenines.io"
    exit 1
}

download_file() {
    url="$1"
    output="$2"

    if command -v wget > /dev/null 2>&1; then
        wget -q -T 10 "$url" -O "$output"
    elif command -v curl > /dev/null 2>&1; then
        curl -sL --connect-timeout 10 "$url" -o "$output"
    else
        return 1
    fi
}

download_with_fallback() {
    filename="$1"
    output="$2"
    r2_url="${R2_BASE_URL}/${filename}"
    github_url="$3"

    print_warning "Downloading ${filename}..."

    # Record which mirror served the file: the manifest has to be read from
    # that same mirror, and verify_from_manifest / install_verified_release_file
    # refuse outright when this is empty. Every shipped copy sets it; the
    # canonical one must too, or the source of truth is a trap.
    DOWNLOAD_SOURCE=""

    # Try R2 first (IPv6 compatible)
    if download_file "$r2_url" "$output" 2>/dev/null; then
        DOWNLOAD_SOURCE="r2"
        print_success "Downloaded from releases.fivenines.io"
        return 0
    fi

    # Fallback to GitHub
    print_warning "R2 mirror unavailable, trying GitHub..."
    if download_file "$github_url" "$output" 2>/dev/null; then
        DOWNLOAD_SOURCE="github"
        print_success "Downloaded from GitHub"
        return 0
    fi

    return 1
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
