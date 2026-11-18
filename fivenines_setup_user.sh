#!/bin/sh

# Fivenines Agent User-Level Setup Script
# For environments without root access (shared hosting, managed VPS, etc.)
#
# Usage: bash fivenines_setup_user.sh YOUR_TOKEN
#        bash fivenines_setup_user.sh --from-system
#
#   --from-system  Move this host's system installation (fivenines_setup.sh) to a
#                  user-level installation for the user running this script. The
#                  agent keeps its token, machine id and state, so the dashboard
#                  keeps the same host. Needs sudo, to read, stop and remove the
#                  system installation (with the release's fivenines_uninstall.sh,
#                  verified against its signed manifest). Adds an @reboot line to
#                  your crontab, since the system agent started at boot. Not on UNRAID.
#
# Environment variables:
#   FIVENINES_AGENT_URL    - Custom download URL for the agent tarball (e.g., feature branch builds).
#                            Unverified unless FIVENINES_AGENT_SHA256 is also set.
#   FIVENINES_AGENT_SHA256 - Expected SHA-256 of the tarball. Overrides the published
#                            SHA256SUMS; the only way to verify a custom URL.
#   FIVENINES_SKIP_VERIFY  - Set to 1 to install WITHOUT verifying the tarball. Unsupported.
#   FIVENINES_ALLOW_UNSIGNED - Set to 1 to install on a host with no openssl, with
#                            checksum-only verification. Without it, a missing openssl
#                            aborts the install (the signature cannot be checked).
#   FIVENINES_REQUIRE_SIGNATURE - Set to 1 to abort even when this installer embeds no
#                            public key at all (the key-rotation escape hatch). A
#                            signature that cannot be checked is already fatal.
#   FIVENINES_INSTALL_DIR  - Custom install directory (default: ~/.local/fivenines)
#   FIVENINES_CONFIG_DIR   - Custom config directory (default: ~/.config/fivenines_agent)
#
# Example with custom build:
#   FIVENINES_AGENT_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/download/feature-branch/fivenines-agent-linux-amd64.tar.gz" bash fivenines_setup_user.sh YOUR_TOKEN
#
# This installs the agent in your home directory and runs as your user.
# Some features (SMART, RAID) won't be available without sudo permissions.

set -e

VERSION="1.0.0"

# Mirror URLs (R2 is IPv6-compatible, GitHub is fallback)
R2_BASE_URL="https://releases.fivenines.io/latest"
GITHUB_RELEASES_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/latest/download"

INSTALL_DIR="${FIVENINES_INSTALL_DIR:-$HOME/.local/fivenines}"
CONFIG_DIR="${FIVENINES_CONFIG_DIR:-$HOME/.config/fivenines_agent}"
LOG_FILE="$INSTALL_DIR/agent.log"
# Never inherited from the environment: ensure_work_dir creates it.
WORK_DIR=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo ""
    printf '%b\n' "${BLUE}===============================================================${NC}"
    printf '%b\n' "${BLUE}  Fivenines Agent - User-Level Installation${NC}"
    printf '%b\n' "${BLUE}===============================================================${NC}"
    echo ""
}

# The message is printed as it is (%s): through %b, a backslash sequence in a
# path it names (a directory another account chose) became an escape.
print_success() {
    printf '%b%s\n' "${GREEN}[+]${NC} " "$1"
}

print_warning() {
    printf '%b%s\n' "${YELLOW}[!]${NC} " "$1"
}

print_error() {
    printf '%b%s\n' "${RED}[-]${NC} " "$1"
}

exit_with_error() {
    print_error "$1"
    echo ""
    echo "For assistance, contact: sebastien@fivenines.io"
    exit 1
}

check_requirements() {
    echo "Checking requirements..."

    # Check for wget or curl
    if command -v wget > /dev/null 2>&1; then
        DOWNLOADER="wget"
        print_success "wget available"
    elif command -v curl > /dev/null 2>&1; then
        DOWNLOADER="curl"
        print_success "curl available"
    else
        exit_with_error "Neither wget nor curl found. Please install one of them."
    fi

    # Check for tar
    if ! command -v tar > /dev/null 2>&1; then
        exit_with_error "tar not found. Please install tar."
    fi
    print_success "tar available"

    # Check we're on Linux
    if [ "$(uname -s)" != "Linux" ]; then
        exit_with_error "This script only supports Linux. Detected: $(uname -s)"
    fi
    print_success "Linux detected"

    echo ""
}

download_file() {
    url="$1"
    output="$2"

    if [ "$DOWNLOADER" = "wget" ]; then
        wget -q -T 10 "$url" -O "$output"
    else
        curl -sL --connect-timeout 10 "$url" -o "$output"
    fi
}

download_with_fallback() {
    filename="$1"
    output="$2"
    r2_url="${R2_BASE_URL}/${filename}"
    github_url="${GITHUB_RELEASES_URL}/${filename}"

    # Record which mirror served the file: the checksum has to be read from
    # that same mirror (see download_sums).
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

    download_file "$url" "$output" 2>/dev/null
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

create_directories() {
    echo "Creating directories..."

    mkdir -p "$INSTALL_DIR"
    print_success "Install directory: $INSTALL_DIR"

    mkdir -p "$CONFIG_DIR"
    print_success "Config directory: $CONFIG_DIR"

    echo ""
}

save_token() {
    token="$1"

    echo "Saving token..."
    printf '%s' "$token" > "$CONFIG_DIR/TOKEN"
    chmod 600 "$CONFIG_DIR/TOKEN"
    print_success "Token saved securely"
    echo ""
}

# One private work directory per run, removed on exit (--from-system needs it
# before the agent is downloaded).
ensure_work_dir() {
    if [ -n "${WORK_DIR:-}" ]; then
        return 0
    fi
    WORK_DIR=$(make_work_dir) || exit_with_error "Failed to create a private temporary directory"
    trap 'rm -rf "$WORK_DIR"' EXIT
}

download_agent() {
    echo "Downloading agent..."

    tarball_name="${BINARY_NAME}.tar.gz"

    # See make_work_dir: /tmp is world-writable, so the download lands
    # somewhere only this process can reach. The CI harness still pre-places
    # a tarball at the old path, which is copied in rather than used in place.
    preplaced_tarball="/tmp/${tarball_name}"
    ensure_work_dir
    tarball_path="${WORK_DIR}/${tarball_name}"

    # Only download_with_fallback sets this; an empty value means the tarball
    # did not come from a mirror that publishes a checksum.
    DOWNLOAD_SOURCE=""

    # Use custom URL if provided, otherwise use fallback mechanism
    if [ "${FIVENINES_TEST_MODE:-}" = "1" ] && [ -f "$preplaced_tarball" ]; then
        print_warning "Using pre-placed tarball at $preplaced_tarball (test mode)"
        cp "$preplaced_tarball" "$tarball_path" || exit_with_error "Failed to stage the pre-placed tarball"
    elif [ -n "${FIVENINES_AGENT_URL:-}" ]; then
        print_warning "Using custom agent URL: $FIVENINES_AGENT_URL"
        download_file "$FIVENINES_AGENT_URL" "$tarball_path" || exit_with_error "Failed to download agent from custom URL"
        print_success "Downloaded from custom URL"
    else
        download_with_fallback "$tarball_name" "$tarball_path" || exit_with_error "Failed to download agent"
    fi

    if ! verify_agent_tarball "$tarball_path" "$tarball_name"; then
        rm -f "$tarball_path"
        exit_with_error "Refusing to install an unverified agent tarball. No agent binary was unpacked; any existing installation is untouched."
    fi

    # Remove the old installation only once the replacement has been verified,
    # so a rejected tarball cannot leave the user with no agent at all.
    if [ -d "$INSTALL_DIR/$BINARY_NAME" ]; then
        rm -rf "${INSTALL_DIR:?}/${BINARY_NAME:?}"
    fi

    tar -xzf "$tarball_path" -C "$INSTALL_DIR" || exit_with_error "Failed to extract agent"
    print_success "Extracted to $INSTALL_DIR"

    rm -f "$tarball_path" 2>/dev/null || true

    # Make executable
    chmod +x "$INSTALL_DIR/$BINARY_NAME/$BINARY_NAME"
    print_success "Agent installed"

    echo ""
}

test_connectivity() {
    echo "Testing connectivity..."

    connected=false

    for host in api.fivenines.io eu.fivenines.io us.fivenines.io; do
        if ping -c 1 -W 3 "$host" > /dev/null 2>&1; then
            print_success "Connected to $host"
            connected=true
            break
        fi
    done

    if [ "$connected" = false ]; then
        # Try with curl/wget as fallback (ping might be blocked)
        if download_file "https://api.fivenines.io/health" "/dev/null" 2>/dev/null; then
            print_success "Connected to api.fivenines.io (HTTPS)"
        else
            print_warning "Could not verify connectivity. The agent may still work."
        fi
    fi

    echo ""
}

# The pgrep -f pattern for an agent run from INSTALL_DIR: anchored on the
# agent's own path (start.sh runs it by that path), so neither another user's
# agent nor a shell or a tail -f that merely names a file in that directory
# ever matches, with the regex characters a path may hold (/home/a+b) escaped.
agent_pattern() {
    printf '^%s/fivenines-agent-' "$(printf '%s' "$1" | sed 's/[][\.*^$+?(){}|]/\\&/g')"
}

# stop.sh, status.sh, logs.sh and refresh.sh. They find the agent two ways:
# by its path (agent_pattern; they used to look for the binary name anywhere
# in any command line, so status.sh could report another user's agent and
# stop.sh or refresh.sh signal it), and by the PID start.sh recorded, when that
# process is an agent. The second catches an agent started under another
# spelling of this directory (a trailing slash, a symlink): start.sh keeps the
# spelling it was written with, while fivenines_update_user.sh rewrites these
# scripts with the one it was given -- a stop.sh trusting the path alone said
# "not running", and the update started a second agent with the same
# identity. The recorded PID is taken only when the binary it runs
# (/proc/PID/exe, resolved) is one of this installation's own (resolved with
# pwd -P), so neither a PID the system has since reused (by a tail -f of the
# agent's log, say) nor another installation's agent under the same account,
# which a command-line shape matched (#324), is ever signalled; /proc/PID/exe
# reads only for this user's own processes. The update rewrites these scripts
# so an existing installation gets them; never start.sh, which carries the
# config directory the installation was made with.
write_control_scripts() {
    # Every path goes into the scripts single-quoted, its own single quotes
    # written as '\'', so a directory name of any spelling stays one word.
    control_dir="'$(printf '%s' "$INSTALL_DIR" | sed "s/'/'\\\\''/g")'"
    control_log="'$(printf '%s' "$INSTALL_DIR/agent.log" | sed "s/'/'\\\\''/g")'"
    control_pattern="'$(agent_pattern "$INSTALL_DIR" | sed "s/'/'\\\\''/g")'"
    control_find=$(cat << EOF
PIDS=\$(pgrep -f $control_pattern 2>/dev/null)
AGENT_PID=\$(cat $control_dir/agent.pid 2>/dev/null)
case "\$AGENT_PID" in
    ''|*[!0-9]*) ;;
    *)
        AGENT_EXE=\$(readlink -f "/proc/\$AGENT_PID/exe" 2>/dev/null)
        AGENT_HOME=\$(cd $control_dir 2>/dev/null && pwd -P)
        if [ -n "\$AGENT_EXE" ] && [ -n "\$AGENT_HOME" ]; then
            case "\$AGENT_EXE" in
                "\$AGENT_HOME"/fivenines-agent-*/fivenines-agent-*) PIDS="\$PIDS \$AGENT_PID" ;;
            esac
        fi
        ;;
esac
PIDS=\$(printf '%s\n' \$PIDS | sort -un | tr '\n' ' ')
PIDS=\${PIDS% }
EOF
)

    cat > "$INSTALL_DIR/stop.sh" << EOF
#!/bin/bash
# Stop the Fivenines agent: every process running this installation's agent.
$control_find
rm -f $control_dir/agent.pid
if [ -n "\$PIDS" ] && kill \$PIDS 2>/dev/null; then
    echo "Agent stopped (PID: \$PIDS)"
else
    echo "Agent not running"
fi
EOF
    chmod +x "$INSTALL_DIR/stop.sh"
    print_success "Created stop.sh"

    cat > "$INSTALL_DIR/status.sh" << EOF
#!/bin/bash
# Check Fivenines agent status
$control_find
if [ -n "\$PIDS" ]; then
    echo "Agent is running (PID: \$PIDS)"
    echo "Log file: "$control_log
    echo ""
    echo "Last 10 log lines:"
    tail -10 $control_log 2>/dev/null || echo "(no log yet)"
else
    echo "Agent is not running"
fi
EOF
    chmod +x "$INSTALL_DIR/status.sh"
    print_success "Created status.sh"

    cat > "$INSTALL_DIR/logs.sh" << EOF
#!/bin/bash
# View Fivenines agent logs
tail -f $control_log
EOF
    chmod +x "$INSTALL_DIR/logs.sh"
    print_success "Created logs.sh"

    cat > "$INSTALL_DIR/refresh.sh" << EOF
#!/bin/bash
# Refresh agent capabilities (after permission changes)
$control_find
if [ -n "\$PIDS" ] && kill -HUP \$PIDS 2>/dev/null; then
    echo "Sent SIGHUP to agent (PID: \$PIDS) - capabilities will refresh"
else
    echo "Agent is not running"
fi
EOF
    chmod +x "$INSTALL_DIR/refresh.sh"
    print_success "Created refresh.sh"
}

# How a crontab line can name INSTALL_DIR's start.sh: the absolute path the
# installers print and, when INSTALL_DIR is under HOME, the ~/ form the README
# shows and its $HOME/ and ${HOME}/ forms; and the absolute path as it reads
# between single quotes, each ' written '\'' (shell_quote, the way
# add_reboot_entry writes a path that needs quoting, #319). Sets
# START_SPELLING_1 to _5 (each the absolute path when it has no other form).
start_spellings() {
    START_SPELLING_1="$1/start.sh"
    START_SPELLING_2="$START_SPELLING_1"
    START_SPELLING_3="$START_SPELLING_1"
    START_SPELLING_4="$START_SPELLING_1"
    START_SPELLING_5=$(printf '%s' "$START_SPELLING_1" | sed "s/'/'\\\\''/g")
    start_rel="${1#"$2"/}"
    if [ -n "$2" ] && [ "$start_rel" != "$1" ]; then
        # The tilde and the dollar signs are the literal text of the line.
        # shellcheck disable=SC2088
        START_SPELLING_2="~/$start_rel/start.sh"
        START_SPELLING_3="\$HOME/$start_rel/start.sh"
        START_SPELLING_4="\${HOME}/$start_rel/start.sh"
    fi
}

create_run_script() {
    echo "Creating helper scripts..."

    # Create start script
    cat > "$INSTALL_DIR/start.sh" << EOF
#!/bin/bash
# Start the Fivenines agent
export CONFIG_DIR="$CONFIG_DIR"
cd "$INSTALL_DIR"
nohup "$INSTALL_DIR/$BINARY_NAME/$BINARY_NAME" >> "$LOG_FILE" 2>&1 &
echo \$! > "$INSTALL_DIR/agent.pid"
echo "Agent started (PID: \$(cat "$INSTALL_DIR/agent.pid"))"
EOF
    chmod +x "$INSTALL_DIR/start.sh"
    print_success "Created start.sh"

    write_control_scripts

    echo ""
}

# Does the agent start.sh just started still run? The PID it recorded, when
# that process runs this installation's binary (/proc/PID/exe, readable for
# this user's own processes only): a pgrep of its path also counted another
# user's process started under that path, and a run that failed read as one
# that started.
agent_started() {
    started_pid=$(cat "$INSTALL_DIR/agent.pid" 2> /dev/null) || return 1
    case "$started_pid" in
        "" | *[!0-9]*) return 1 ;;
    esac
    started_exe=$(readlink -f "/proc/$started_pid/exe" 2> /dev/null) || return 1
    [ -n "$started_exe" ] \
        && [ "$started_exe" = "$(readlink -f "$INSTALL_DIR/$BINARY_NAME/$BINARY_NAME" 2> /dev/null)" ]
}

# Non-zero when the agent is not running two seconds after start.sh: a plain
# install only warns, --from-system fails (#315).
start_agent() {
    echo "Starting agent..."

    "$INSTALL_DIR/start.sh"

    # Wait a moment and check if it's running
    sleep 2

    if agent_started; then
        print_success "Agent is running"
        echo ""
        return 0
    fi
    print_warning "Agent may have failed to start. Check logs:"
    echo "  $INSTALL_DIR/logs.sh"
    echo ""
    return 1
}

# The shell word for $1: as it is when it holds only characters no shell reads
# specially, else between single quotes, each ' written '\''. cron hands a
# crontab line to sh, so an unquoted path with a space ran its first word
# (#319).
shell_quote() {
    case "$1" in
        "" | *[!A-Za-z0-9_./+-]*)
            printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
            ;;
        *)
            printf '%s' "$1"
            ;;
    esac
}

# The @reboot line that starts this installation, or nothing and a non-zero
# status when its path holds a % or a new line: cron reads a % as the end of
# the command (and the escape differs: cronie and Vixie cron take \%, while
# BusyBox's crond keeps the backslash), and a new line ends a crontab line.
reboot_line() {
    case "$INSTALL_DIR" in
        *%* | *"
"*)
            return 1
            ;;
    esac
    printf '@reboot %s' "$(shell_quote "$INSTALL_DIR/start.sh")"
}

# What a message tells the user to do so the agent starts at boot, ending it:
# add the @reboot line (last, so it can be copied whole), or, when its path
# cannot be carried by one (reboot_line), start it from a script of their own;
# never the raw line, which cron would misread.
reboot_advice() {
    if reboot_advice_line=$(reboot_line); then
        printf 'add this line to your crontab (crontab -e): %s' "$reboot_advice_line"
    else
        printf 'start %s at boot from a script of your own (its path holds a %% or a new line, which a crontab line cannot carry)' "$INSTALL_DIR/start.sh"
    fi
}

print_crontab_instructions() {
    printf '%b\n' "${BLUE}===============================================================${NC}"
    printf '%b\n' "${BLUE}  Auto-Start on Reboot (Optional)${NC}"
    printf '%b\n' "${BLUE}===============================================================${NC}"
    echo ""
    echo "To automatically start the agent when your server reboots,"
    echo "add this line to your crontab (run: crontab -e):"
    echo ""
    if crontab_line=$(reboot_line); then
        printf '%b%s%b\n' "$GREEN" "$crontab_line" "$NC"
    else
        echo "  (the path $INSTALL_DIR holds a % or a new line, which a crontab line"
        echo "  cannot carry as is: start $INSTALL_DIR/start.sh from a script of your own)"
    fi
    echo ""
}

print_final_instructions() {
    printf '%b\n' "${BLUE}===============================================================${NC}"
    printf '%b\n' "${BLUE}  Installation Complete!${NC}"
    printf '%b\n' "${BLUE}===============================================================${NC}"
    echo ""
    echo "Management commands:"
    echo "  $INSTALL_DIR/start.sh    - Start the agent"
    echo "  $INSTALL_DIR/stop.sh     - Stop the agent"
    echo "  $INSTALL_DIR/status.sh   - Check agent status"
    echo "  $INSTALL_DIR/logs.sh     - View agent logs"
    echo "  $INSTALL_DIR/refresh.sh  - Refresh capabilities (after permission changes)"
    echo ""
    if [ "$FROM_SYSTEM" = "1" ]; then
        echo "The system agent now runs as this user-level installation, with the"
        echo "same token and machine id: the dashboard keeps the same host."
        echo ""
    fi
    if [ "${REBOOT_ENTRY_ADDED:-0}" != "1" ]; then
        print_crontab_instructions
    fi
    printf '%b\n' "${YELLOW}Note:${NC} Some features (SMART, RAID) are unavailable without sudo."
    echo ""
    echo "Happy monitoring!"
    echo ""
}

# ---------------------------------------------------------------------------
# --from-system: move the system installation (fivenines_setup.sh) to this
# user-level one.
#
# The user-level agent takes over the system agent's identity -- its TOKEN
# (the per-host token it swapped the enrollment token for) and its MACHINE_ID
# -- and its state, so the dashboard keeps the same host instead of enrolling
# a second one. The system agent is stopped before its state is read and
# before this one starts (two agents with one identity would report as one
# host, twice). The system installation is removed by the release's own
# fivenines_uninstall.sh, so this script carries no second copy of what that
# takes; it runs as root, so it is verified before anything changes.
# ---------------------------------------------------------------------------

# What the agent keeps in its config directory that the new installation
# carries over: see fivenines_setup.sh, which carries the same files the other
# way (ci/build-scripts.sh keeps the two lines equal).
STATE_FILES="TOKEN MACHINE_ID last_capture_id journal_units.allow"
# Not carried as such: /etc/fivenines_agent belongs to the fivenines account
# (0750, so the agent can write its state), so its .env is that account's
# choice, and loaded into this user's agent it would pick the environment of a
# process run by a user who can use sudo. It is copied as .env.system, which
# nothing reads, for the user to review. image_inventory_done is only a cache:
# each image is scanned once again.
SYSTEM_ENV_COPY=".env.system"
# What this run wrote into the user's config directory, all of it taken back
# when the move is undone (nothing was there before: the preflight refuses
# one).
COPIED_STATE_FILES=""
# A state file is a few KB at most: anything bigger is not one.
STATE_FILE_MAX=16777216
SYSTEM_CONFIG_DIR="/etc/fivenines_agent"

# as_root SCRIPT [ARG...]: run SCRIPT with sh through sudo, with the ARGs as
# $1, $2... They are never pasted into SCRIPT, so a path is never parsed as
# shell code.
as_root() {
    as_root_script="$1"
    shift
    sudo sh -c "$as_root_script" sh "$@"
}

# A user-level install on a host that runs the system agent too: both would
# run, as two hosts. Not refused (it may be deliberate), but said, with the
# way to move it instead.
hint_system_installation() {
    if [ -d "$SYSTEM_CONFIG_DIR" ]; then
        print_warning "This host has a system installation of the agent ($SYSTEM_CONFIG_DIR): this one would run beside it, as another host."
        print_warning "To move the system agent to this user instead, keeping its host: bash fivenines_setup_user.sh --from-system"
        echo ""
    fi
}

fetch_system_uninstaller() {
    UNINSTALLER="${WORK_DIR}/fivenines_uninstall.sh"
    # The test harness pre-places it, like the tarball. Any local user can
    # create a file in /tmp, and this one runs as root: only one owned by root
    # or by this user, and writable by no one else, is taken.
    if [ "${FIVENINES_TEST_MODE:-}" = "1" ] && [ -f /tmp/fivenines_uninstall.sh ] \
        && [ -n "$(find /tmp/fivenines_uninstall.sh -prune \( -user 0 -o -user "$(id -u)" \) ! -perm -020 ! -perm -002 2>/dev/null)" ]; then
        print_warning "Using pre-placed fivenines_uninstall.sh (test mode)"
        cp /tmp/fivenines_uninstall.sh "$UNINSTALLER"
        return
    fi
    download_with_fallback "fivenines_uninstall.sh" "$UNINSTALLER" || return 1
    if [ "${FIVENINES_SKIP_VERIFY:-}" = "1" ]; then
        print_warning "FIVENINES_SKIP_VERIFY=1 - fivenines_uninstall.sh will run as root UNVERIFIED."
        return 0
    fi
    verify_from_manifest "$UNINSTALLER" "fivenines_uninstall.sh"
}

# Before anything is installed, so a refusal leaves the host as it was.
preflight_system_takeover() {
    if [ "$(id -u)" = "0" ]; then
        exit_with_error "Run --from-system as the user the agent is to run as, not as root."
    fi
    if [ -f /etc/unraid-version ]; then
        exit_with_error "--from-system is not supported on UNRAID."
    fi
    if [ -e "$CONFIG_DIR/TOKEN" ] || [ -L "$CONFIG_DIR/TOKEN" ]; then
        exit_with_error "$CONFIG_DIR/TOKEN exists: this user already has a user-level installation. If an earlier --from-system stopped once the system installation was removed, that TOKEN is the agent's identity: start it with $INSTALL_DIR/start.sh. Otherwise remove it first with fivenines_uninstall_user.sh."
    fi
    # An installation here with its config elsewhere (FIVENINES_CONFIG_DIR):
    # its agent would be replaced while it runs, and the move start a second.
    # A start.sh for this config directory, with no TOKEN there, starts no
    # agent: what an earlier --from-system left when it was undone.
    if { [ -e "$INSTALL_DIR/start.sh" ] || [ -L "$INSTALL_DIR/start.sh" ]; } \
        && ! grep -qxF "export CONFIG_DIR=\"$CONFIG_DIR\"" "$INSTALL_DIR/start.sh" 2>/dev/null; then
        exit_with_error "$INSTALL_DIR/start.sh exists, for another config directory: this user already has a user-level installation there. Remove it first with fivenines_uninstall_user.sh (with the FIVENINES_INSTALL_DIR and FIVENINES_CONFIG_DIR it was installed with)."
    fi
    # Any other state file would be replaced, and deleted if the move is undone.
    for state_file in $STATE_FILES "$SYSTEM_ENV_COPY"; do
        if [ -e "$CONFIG_DIR/$state_file" ] || [ -L "$CONFIG_DIR/$state_file" ]; then
            exit_with_error "$CONFIG_DIR/$state_file exists, left by an earlier installation: the move would replace it, and delete it if undone. Move it aside and re-run."
        fi
    done
    if ! command -v sudo > /dev/null 2>&1; then
        exit_with_error "--from-system needs sudo, to read, stop and remove the system installation."
    fi
    echo "Moving the system installation needs sudo: to read its token, then stop and remove it."
    sudo -v || exit_with_error "sudo did not authenticate: nothing was changed."
    # The quoted $1 is as_root's argument, expanded by root's shell.
    # shellcheck disable=SC2016
    if ! as_root 'test -f "$1" && test -s "$1"' "$SYSTEM_CONFIG_DIR/TOKEN"; then
        exit_with_error "No system installation found: $SYSTEM_CONFIG_DIR/TOKEN is missing or empty."
    fi
    ensure_work_dir
    fetch_system_uninstaller || exit_with_error "Could not get a verified fivenines_uninstall.sh: nothing was changed."
    print_success "Moving the system installation to the user-level installation of $(id -un) ($INSTALL_DIR)"
    echo ""
}

# Each state file is copied by root, through sudo, into a directory of its own
# inside this user's private work directory, and handed over (chown) to this
# user, who checks it and puts it in the config directory, after the system
# agent stopped (it may have just swapped its token). Read through sudo's
# stdout instead, it was recorded by sudo's I/O log under "Defaults
# log_output" (audited hosts, often shipped off the host): the TOKEN, and with
# it the host's configuration and every service credential it carries (#318).
# A file that exists but is not a regular file stops the move rather than
# being dropped: a journal allowlist left behind would let the agent read
# every unit's journal.
copy_system_state() {
    state_stash="${WORK_DIR}/system_state"
    mkdir "$state_stash" || return 1
    for state_file in $STATE_FILES .env; do
        state_rc=0
        # shellcheck disable=SC2016
        as_root '
            if [ ! -e "$1" ] && [ ! -L "$1" ]; then exit 3; fi
            if [ -L "$1" ] || [ ! -f "$1" ]; then exit 4; fi
            size=$(wc -c < "$1") || exit 5
            size=${size##* }
            case "$size" in
                "" | *[!0-9]*) exit 5 ;;
            esac
            if [ "$size" -gt "$3" ]; then exit 6; fi
            umask 077
            # At most one byte past the limit is read: the file may have grown
            # since its size was read, and root must not copy it whole.
            rm -f "$2" && head -c "$(($3 + 1))" -- "$1" > "$2" || exit 5
            size=$(wc -c < "$2") || exit 5
            size=${size##* }
            if [ "$size" -gt "$3" ]; then rm -f "$2"; exit 6; fi
            chown "$4" "$2" || exit 5' \
            "$SYSTEM_CONFIG_DIR/$state_file" "$state_stash/$state_file" "$STATE_FILE_MAX" "$(id -u)" \
            > /dev/null || state_rc=$?
        case "$state_rc" in
            0) ;;
            3)
                continue
                ;;
            4)
                print_error "$SYSTEM_CONFIG_DIR/$state_file is not a regular file: fix or remove it, then re-run."
                return 1
                ;;
            6)
                print_error "$SYSTEM_CONFIG_DIR/$state_file is larger than any agent state file."
                return 1
                ;;
            *)
                print_error "Could not read $SYSTEM_CONFIG_DIR/$state_file."
                return 1
                ;;
        esac
        # What root copied, as this user reads it.
        if [ ! -f "$state_stash/$state_file" ] || [ ! -r "$state_stash/$state_file" ] \
            || [ "$(wc -c < "$state_stash/$state_file")" -gt "$STATE_FILE_MAX" ]; then
            print_error "Could not read $SYSTEM_CONFIG_DIR/$state_file."
            return 1
        fi
    done
    if [ ! -s "$state_stash/TOKEN" ]; then
        print_error "$SYSTEM_CONFIG_DIR/TOKEN is empty."
        return 1
    fi
    for state_file in $STATE_FILES .env; do
        if [ ! -f "$state_stash/$state_file" ]; then
            continue
        fi
        state_dest="$state_file"
        if [ "$state_file" = ".env" ]; then
            state_dest="$SYSTEM_ENV_COPY"
        fi
        COPIED_STATE_FILES="$COPIED_STATE_FILES $state_dest"
        if ! (umask 077 && cp "$state_stash/$state_file" "$CONFIG_DIR/$state_dest") \
            || ! chmod 600 "$CONFIG_DIR/$state_dest"; then
            print_error "Could not write $CONFIG_DIR/$state_dest."
            return 1
        fi
        if [ "$state_file" = ".env" ]; then
            print_warning "$SYSTEM_CONFIG_DIR/.env was copied to $CONFIG_DIR/$SYSTEM_ENV_COPY, which the agent does not read: the fivenines account could write it. Review it, and rename it to .env if you need it."
        else
            print_success "Carried over $state_file"
        fi
    done
}

# What the service's own start would do; used to put the system agent back
# when the move fails before anything was removed. Only what was so before
# the move: started again only if it ran, and enabled again only if it was
# enabled (fivenines_uninstall.sh disables the service before it removes the
# TOKEN, so undone between the two it is enabled again, not only started),
# so an undone move never brings back a system agent the operator had stopped
# or disabled (#325).
restart_system_agent() {
    if [ "${FIVENINES_TEST_MODE:-}" = "1" ]; then
        return 0
    fi
    restart_rc=0
    # shellcheck disable=SC2016
    as_root '
        if [ -f /etc/systemd/system/fivenines-agent.service ] && command -v systemctl > /dev/null 2>&1; then
            if [ "$1" = 1 ]; then
                systemctl enable fivenines-agent.service > /dev/null 2>&1 || true
            fi
            if [ "$2" = 1 ]; then
                systemctl start fivenines-agent.service
            fi
        elif [ -f /etc/init.d/fivenines-agent ] && command -v rc-service > /dev/null 2>&1; then
            if [ "$1" = 1 ]; then
                rc-update add fivenines-agent default > /dev/null 2>&1 || true
            fi
            if [ "$2" = 1 ]; then
                rc-service fivenines-agent start
            fi
        else
            exit 3
        fi' "$SYSTEM_AGENT_ENABLED" "$SYSTEM_AGENT_ACTIVE" || restart_rc=$?
    case "$restart_rc" in
        0)
            if [ "$SYSTEM_AGENT_ACTIVE" != "1" ]; then
                print_warning "The system agent was not running before the move: it was left stopped."
            fi
            ;;
        # fivenines_uninstall.sh removes the service definition before the
        # TOKEN: cut between the two, it leaves an identity no service starts.
        3) print_warning "The system agent was not started again: its service definition is gone, while its TOKEN is still in $SYSTEM_CONFIG_DIR. Re-run --from-system to finish the move: it carries that TOKEN over again (removing the system installation first would lose it)." ;;
        *) print_warning "Could not start the system agent again: sudo systemctl start fivenines-agent (or rc-service fivenines-agent start)" ;;
    esac
}

# A move that fails, or is interrupted, between the system agent's stop and
# its removal: take back what was copied (no second copy of that identity is
# left behind), and start the system agent again.
abort_system_takeover() {
    trap '' INT TERM HUP
    # The copy is taken back only when the system installation still has its
    # TOKEN. Once the uninstaller removed it, the copy is the agent's only
    # identity: kept, and said. When sudo cannot tell either way, kept too:
    # a second copy on disk can be removed, a lost identity cannot be rebuilt.
    # shellcheck disable=SC2016
    if as_root 'test -e "$1/TOKEN"' "$SYSTEM_CONFIG_DIR"; then
        for state_file in $COPIED_STATE_FILES; do
            rm -f "${CONFIG_DIR:?}/${state_file:?}"
        done
        restart_system_agent
        exit_with_error "$1"
    fi
    # shellcheck disable=SC2016
    if as_root '! test -e "$1/TOKEN"' "$SYSTEM_CONFIG_DIR"; then
        exit_with_error "Stopped after the system installation was removed: the agent's identity is now in $CONFIG_DIR. Start the agent with $INSTALL_DIR/start.sh, and $(reboot_advice)"
    fi
    exit_with_error "Stopped, and sudo could not tell whether $SYSTEM_CONFIG_DIR/TOKEN still exists. If it does, remove what was copied to $CONFIG_DIR and start the system agent again; if it does not, start this one with $INSTALL_DIR/start.sh."
}

# The agent this run extracted must run as this user before the system
# installation is removed (#315): a home mounted noexec (common on hardened
# hosts), or any other exec failure, ended in a removed system installation
# and a run that read as a success while the host no longer reported.
# --version exits before the agent module is imported.
check_agent_runs() {
    if "$INSTALL_DIR/$BINARY_NAME/$BINARY_NAME" --version > /dev/null 2>&1; then
        return 0
    fi
    exit_with_error "The agent extracted to $INSTALL_DIR/$BINARY_NAME does not run as $(id -un) (is that file system mounted noexec?), so the system installation was not changed. Install it in a directory where this user may run programs (FIVENINES_INSTALL_DIR), and re-run."
}

# Once this installation is in place (not started).
take_over_system_install() {
    # Not interrupted halfway: stopped, the system agent would stay stopped,
    # nothing yet armed to start it again.
    trap '' INT TERM HUP
    # What an undone move restores (#325), and the uid of the system agent's
    # account, recorded before the uninstaller removes it: its processes are
    # told from any other user's by it (#306). When sudo cannot tell, the
    # service is taken as it is by default, enabled and running.
    SYSTEM_AGENT_ENABLED=1
    SYSTEM_AGENT_ACTIVE=1
    SYSTEM_AGENT_UID=""
    if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
        system_agent_state=0
        # shellcheck disable=SC2016
        as_root '
            state=0
            if [ -f /etc/systemd/system/fivenines-agent.service ] && command -v systemctl > /dev/null 2>&1; then
                systemctl is-enabled --quiet fivenines-agent.service 2> /dev/null || state=$((state + 1))
                systemctl is-active --quiet fivenines-agent.service 2> /dev/null || state=$((state + 2))
            elif [ -f /etc/init.d/fivenines-agent ] && command -v rc-service > /dev/null 2>&1; then
                rc-update show default 2> /dev/null | grep -q fivenines-agent || state=$((state + 1))
                rc-service fivenines-agent status > /dev/null 2>&1 || state=$((state + 2))
            fi
            exit $((10 + state))' > /dev/null 2>&1 || system_agent_state=$?
        case "$system_agent_state" in
            11) SYSTEM_AGENT_ENABLED=0 ;;
            12) SYSTEM_AGENT_ACTIVE=0 ;;
            13)
                SYSTEM_AGENT_ENABLED=0
                SYSTEM_AGENT_ACTIVE=0
                ;;
        esac
        SYSTEM_AGENT_UID=$(as_root 'id -u fivenines' 2> /dev/null | tail -n 1)
        case "$SYSTEM_AGENT_UID" in
            "" | *[!0-9]*) SYSTEM_AGENT_UID="" ;;
        esac
        print_warning "Stopping the system agent..."
        as_root '
            if [ -f /etc/systemd/system/fivenines-agent.service ] && command -v systemctl > /dev/null 2>&1; then
                systemctl stop fivenines-agent.service
            elif [ -f /etc/init.d/fivenines-agent ] && command -v rc-service > /dev/null 2>&1; then
                rc-service fivenines-agent stop
            fi' || exit_with_error "Could not stop the system agent: nothing was moved."
    else
        print_warning "Skipping the system agent stop (test mode)"
    fi

    # Armed until the end of the run: before the uninstaller removed the
    # system TOKEN, an interrupt takes the copy back and restarts the system
    # agent; after it, it keeps the copy and says how to start this agent.
    trap 'abort_system_takeover "Interrupted: the system installation was not changed."' INT TERM HUP

    if ! copy_system_state; then
        abort_system_takeover "Could not carry the system agent's state over: the system installation was not changed."
    fi

    print_warning "Removing the system installation..."
    # The verified uninstaller still sits in this user's private work
    # directory: only this user's own processes could have rewritten it since,
    # and those could as well wrap sudo itself (an alias, PATH) -- the trust
    # the README's own wget && sudo bash commands rest on.
    # shellcheck disable=SC2016
    if ! as_root 'cd "$1" && FIVENINES_TEST_MODE="$2" sh ./fivenines_uninstall.sh' \
        "$WORK_DIR" "${FIVENINES_TEST_MODE:-}"; then
        print_warning "fivenines_uninstall.sh reported an error."
    fi
    # The system TOKEN must be gone, not merely the agent stopped: a service
    # that still has it would start at boot beside this agent, with the same
    # identity. Then the copy is taken back, and the identity stays where it
    # was. A sudo that fails reads as not gone.
    # shellcheck disable=SC2016
    if ! as_root '! test -e "$1/TOKEN"' "$SYSTEM_CONFIG_DIR"; then
        abort_system_takeover "fivenines_uninstall.sh did not remove the system installation: what was copied was taken back, and the system agent restarted if it could be. Check it (sudo systemctl status fivenines-agent), fix what failed, and re-run."
    fi
    # Past this point the identity lives only in this user's config, so a
    # leftover service definition is said, never undone: without its TOKEN it
    # cannot start.
    if ! as_root '! test -e /etc/systemd/system/fivenines-agent.service && ! test -e /etc/init.d/fivenines-agent'; then
        print_warning "The fivenines-agent service definition is still installed (it cannot start without its TOKEN): remove it with fivenines_uninstall.sh."
    fi
    # Never two agents with one identity: if the system agent survived its
    # removal, this one is installed but not started. Only a process of the
    # system agent's account counts (#306): any local user can start one whose
    # command line starts with /opt/fivenines/, which kept this agent from
    # starting once the system installation was gone. With that uid unknown,
    # any process does.
    # shellcheck disable=SC2016
    if [ "${FIVENINES_TEST_MODE:-}" != "1" ] && as_root '
        for pid in $(pgrep -f "^/opt/fivenines/" 2> /dev/null); do
            uid=$(awk "/^Uid:/ { print \$2; exit }" "/proc/$pid/status" 2> /dev/null)
            if [ -z "$1" ] || [ "$uid" = "$1" ]; then
                exit 0
            fi
        done
        exit 1' "$SYSTEM_AGENT_UID" > /dev/null 2>&1; then
        exit_with_error "The system agent still runs. This agent's identity is in $CONFIG_DIR. Stop and disable the system agent (sudo systemctl disable fivenines-agent; sudo systemctl stop fivenines-agent), then start this one with $INSTALL_DIR/start.sh, and $(reboot_advice)"
    fi
    # The system installation is gone: what is left (start the agent, add its
    # @reboot line) takes seconds, and cut halfway it would leave an agent
    # running with no boot entry, and a message saying to start it again.
    trap '' INT TERM HUP
    echo ""
}

# The system agent started at boot; this one does too, from the crontab line
# print_crontab_instructions describes. Already there when an @reboot line
# runs start.sh, in any of its spellings, as a word of its own (#320): a line
# that merely names it (a backup cp of it, a commented-out line) starts
# nothing. And the crontab is written only once it was read: crontab -l fails
# with "no crontab for USER" (BusyBox: "No such file or directory") when there
# is none, and any other failure (a transient error, cron.deny) read as an
# empty crontab, which the write then replaced with the @reboot line alone
# (#321).
add_reboot_entry() {
    if ! command -v crontab > /dev/null 2>&1; then
        print_warning "No crontab command here, so nothing starts the agent at boot."
        return 1
    fi
    if ! new_reboot_line=$(reboot_line); then
        print_warning "Not added to your crontab: the path $INSTALL_DIR holds a % or a new line, which a crontab line cannot carry as is."
        return 1
    fi
    ensure_work_dir
    if reboot_entries=$(LC_ALL=C crontab -l 2> "$WORK_DIR/crontab.err"); then
        :
    elif grep -qi -e 'no crontab for' -e 'No such file or directory' "$WORK_DIR/crontab.err"; then
        reboot_entries=""
    else
        print_warning "Could not read your crontab ($(head -n 1 "$WORK_DIR/crontab.err")): it was left as it is, and nothing starts the agent at boot."
        return 1
    fi
    start_spellings "$INSTALL_DIR" "$HOME"
    # The spellings go through the environment: awk -v would read the
    # backslashes a path may hold as escapes.
    if printf '%s\n' "$reboot_entries" | S1="$START_SPELLING_1" S2="$START_SPELLING_2" \
        S3="$START_SPELLING_3" S4="$START_SPELLING_4" S5="$START_SPELLING_5" awk '
        # Does cmd run s, as a word of its own: preceded by nothing, a blank,
        # an opening quote or a shell separator, and followed likewise?
        function runs(cmd, s,    rest, i, before, after) {
            rest = cmd
            while (s != "" && (i = index(rest, s)) > 0) {
                before = (i > 1) ? substr(rest, i - 1, 1) : ""
                after = substr(rest, i + length(s), 1)
                if ((before == "" || index(" \t;&|(\"\047", before) > 0) \
                    && (after == "" || index(" \t;&|)<>\"\047", after) > 0)) {
                    return 1
                }
                rest = substr(rest, i + 1)
            }
            return 0
        }
        $1 == "@reboot" {
            cmd = $0
            sub(/^[ \t]*@reboot[ \t]+/, "", cmd)
            if (runs(cmd, ENVIRON["S1"]) || runs(cmd, ENVIRON["S2"]) || runs(cmd, ENVIRON["S3"]) \
                || runs(cmd, ENVIRON["S4"]) || runs(cmd, ENVIRON["S5"])) {
                found = 1
            }
        }
        END { exit !found }'; then
        print_success "Your crontab already starts the agent at boot"
        return 0
    fi
    if { if [ -n "$reboot_entries" ]; then printf '%s\n' "$reboot_entries"; fi; printf '%s\n' "$new_reboot_line"; } | crontab -; then
        print_success "Added to your crontab: $new_reboot_line"
        echo ""
        return 0
    fi
    print_warning "Could not add the @reboot line to your crontab."
    return 1
}

# Test mode: skip network calls and service management for CI testing
if [ "${FIVENINES_TEST_MODE:-}" = "1" ]; then
  print_warning "WARNING: Test mode enabled - skipping network checks and agent startup"
fi

# Main execution
print_banner

usage() {
    echo "Usage: bash $0 YOUR_TOKEN"
    echo "       bash $0 --from-system"
    echo ""
    echo "Get your token from https://fivenines.io"
    exit 1
}

# Only this exact word is an option: anything else is the token, since a
# token may itself start with a dash.
TOKEN=""
FROM_SYSTEM=0
POSITIONAL_COUNT=0
for arg in "$@"; do
    case "$arg" in
        --from-system) FROM_SYSTEM=1 ;;
        *)
            POSITIONAL_COUNT=$((POSITIONAL_COUNT + 1))
            if [ "$POSITIONAL_COUNT" -eq 1 ]; then
                TOKEN="$arg"
            fi
            ;;
    esac
done
if [ "$FROM_SYSTEM" = "1" ]; then
    # The token comes from the system installation.
    if [ "$POSITIONAL_COUNT" -gt 0 ]; then
        usage
    fi
elif [ -z "$TOKEN" ]; then
    usage
# Validate token format (basic check)
elif [ ${#TOKEN} -lt 10 ]; then
    exit_with_error "Token seems too short. Please check your token."
fi

check_requirements

# Refuse a host no release has a binary for (issue #170).
select_agent_binary || exit_with_error "No agent binary runs on this host -- nothing was installed."

# Refuse early if this host cannot verify a release at all (issue #154).
# --from-system also runs the release's fivenines_uninstall.sh as root, which
# is verified against the signed manifest even when FIVENINES_AGENT_SHA256
# pins the tarball: the scope the system installers pass for their startup
# definitions.
PREFLIGHT_SCOPE=""
if [ "$FROM_SYSTEM" = "1" ]; then
    PREFLIGHT_SCOPE="with-startup-files"
fi
verification_preflight "$PREFLIGHT_SCOPE" || exit_with_error "Cannot verify a release on this host -- nothing was installed."
if [ "$FROM_SYSTEM" = "1" ]; then
    preflight_system_takeover
else
    hint_system_installation
fi
create_directories
if [ "$FROM_SYSTEM" != "1" ]; then
    save_token "$TOKEN"
fi
if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
  test_connectivity
else
  print_warning "Skipping connectivity test (test mode)"
fi
download_agent
create_run_script
if [ "$FROM_SYSTEM" = "1" ]; then
    check_agent_runs
    take_over_system_install
fi
AGENT_START_FAILED=0
if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
  if ! start_agent; then
      AGENT_START_FAILED=1
  fi
else
  print_warning "Skipping agent startup (test mode)"
fi
REBOOT_ENTRY_ADDED=0
if [ "$FROM_SYSTEM" = "1" ] && add_reboot_entry; then
    REBOOT_ENTRY_ADDED=1
fi
# --from-system set it in take_over_system_install: the move is complete.
trap - INT TERM HUP
# The system installation is gone: an agent that did not start here is a
# host no longer reporting, so the run fails rather than end in success
# (#315). Its @reboot line was added all the same.
if [ "$FROM_SYSTEM" = "1" ] && [ "$AGENT_START_FAILED" = "1" ]; then
    if [ "$REBOOT_ENTRY_ADDED" = "1" ]; then
        exit_with_error "The system installation was removed, but this agent did not start: its identity is in $CONFIG_DIR. Check $INSTALL_DIR/logs.sh, fix what failed, and start it with $INSTALL_DIR/start.sh (your crontab starts it at boot)."
    fi
    exit_with_error "The system installation was removed, but this agent did not start: its identity is in $CONFIG_DIR. Check $INSTALL_DIR/logs.sh, fix what failed, start it with $INSTALL_DIR/start.sh, and $(reboot_advice)"
fi
print_final_instructions

# Clean up script
rm -f "$0" 2>/dev/null || true
