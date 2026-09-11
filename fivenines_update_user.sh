#!/bin/sh

# Fivenines Agent User-Level Update Script
# Updates an existing user-level installation
#
# Usage: bash fivenines_update_user.sh
#
# Environment variables:
#   FIVENINES_AGENT_URL    - Custom download URL for the agent tarball (e.g., pre-release builds).
#                            Unverified unless FIVENINES_AGENT_SHA256 is also set.
#   FIVENINES_AGENT_SHA256 - Expected SHA-256 of the tarball. Overrides the published
#                            SHA256SUMS; the only way to verify a custom URL.
#   FIVENINES_SKIP_VERIFY  - Set to 1 to install WITHOUT verifying the tarball. Unsupported.
#   FIVENINES_REQUIRE_SIGNATURE - Set to 1 to abort unless the release signature over
#                            SHA256SUMS verifies (default: warn and fall back to the checksum).
#   FIVENINES_INSTALL_DIR  - Custom install directory (default: ~/.local/fivenines)
#   FIVENINES_CONFIG_DIR   - Custom config directory (default: ~/.config/fivenines_agent)
#
# Example with custom build:
#   FIVENINES_AGENT_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/download/feature-branch-abc1234/fivenines-agent-linux-amd64.tar.gz" bash fivenines_update_user.sh

set -e

# Mirror URLs (R2 is IPv6-compatible, GitHub is fallback)
R2_BASE_URL="https://releases.fivenines.io/latest"
GITHUB_RELEASES_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/latest/download"

INSTALL_DIR="${FIVENINES_INSTALL_DIR:-$HOME/.local/fivenines}"
CONFIG_DIR="${FIVENINES_CONFIG_DIR:-$HOME/.config/fivenines_agent}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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
# EMPTY output means signature verification is not armed yet: the installers
# fall back to checksum-only and say so out loud. Filling this in arms
# signature verification fleet-wide on the next release. To arm it:
#
#   openssl ecparam -name prime256v1 -genkey -noout -out fivenines-release.key
#   openssl ec -in fivenines-release.key -pubout
#
# Put the PRIVATE key in the RELEASE_SIGNING_KEY repository secret, and paste
# the public key PEM between the PUBKEY markers below - in this file and in
# all four install scripts. ci/build-scripts.sh --check enforces that the
# five copies stay identical, so a key pasted into only some of them fails CI.
release_signing_pubkey() {
    cat <<'PUBKEY'
PUBKEY
}

# Verify the detached signature over SHA256SUMS. Three outcomes, and the
# difference between the last two is the whole point:
#   0 - verified against the embedded public key
#   1 - a signature was expected and did NOT verify. Always fatal.
#   2 - cannot be checked here (no key embedded yet, or no openssl on this
#       host). The caller decides; by default that is a warning, because an
#       attacker who owns the release bucket does not get to uninstall
#       openssl from the target host - the two are independent.
verify_sums_signature() {
    sums_file="$1"
    sig_file="$2"

    pubkey=$(release_signing_pubkey)
    if [ -z "$pubkey" ]; then
        return 2
    fi

    if ! command -v openssl > /dev/null 2>&1; then
        print_warning "No openssl on this host: the release signature cannot be checked."
        return 2
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

# Check an agent tarball before it is unpacked. The expected digest comes from
# FIVENINES_AGENT_SHA256 when the operator pinned one, otherwise from the
# SHA256SUMS the same mirror publishes next to the tarball, which is itself
# checked against the embedded release public key. A non-zero return means the
# tarball must not be installed.
#
# The two layers do different jobs. The digest alone proves the bytes arrived
# intact and are the ones that mirror published - a truncated download, a
# half-finished mirror sync, a swapped asset. It cannot catch an attacker who
# owns the mirror, because they would rewrite SHA256SUMS too. The signature
# is what closes that: the signing key lives in a repository secret, not in
# the bucket, so a manifest the attacker rewrote will not verify (issue #143).
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

    sums_path="${tarball}.SHA256SUMS"
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

    if [ "$sig_status" -eq 2 ]; then
        if [ "${FIVENINES_REQUIRE_SIGNATURE:-}" = "1" ]; then
            print_error "FIVENINES_REQUIRE_SIGNATURE=1, but the release signature could not be checked."
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

    verify_sha256 "$tarball" "$expected_sha256" "$asset_name"
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

# Test mode: skip network calls and service management for CI testing
if [ "${FIVENINES_TEST_MODE:-}" = "1" ]; then
  print_warning "WARNING: Test mode enabled - skipping agent stop/start"
fi

echo ""
printf '%b\n' "${BLUE}===============================================================${NC}"
printf '%b\n' "${BLUE}  Fivenines Agent - User-Level Update${NC}"
printf '%b\n' "${BLUE}===============================================================${NC}"
echo ""

if [ -n "${FIVENINES_AGENT_URL:-}" ]; then
    printf '%b\n' "${YELLOW}  Custom build URL detected${NC}"
    echo ""
fi

# Check if installation exists
if [ ! -d "$INSTALL_DIR" ]; then
    exit_with_error "No installation found at $INSTALL_DIR"
fi

# Check for token
if [ ! -f "$CONFIG_DIR/TOKEN" ]; then
    exit_with_error "Token file not found at $CONFIG_DIR/TOKEN"
fi

print_success "Found existing installation"

# Detect architecture and libc
ARCH=$(uname -m)
LIBC_TYPE=$(detect_libc)
if [ "$LIBC_TYPE" = "musl" ]; then
    case "$ARCH" in
        x86_64|amd64)
            BINARY_NAME="fivenines-agent-alpine-amd64"
            ;;
        aarch64|arm64)
            BINARY_NAME="fivenines-agent-alpine-arm64"
            ;;
        *)
            exit_with_error "Unsupported architecture: $ARCH"
            ;;
    esac
else
    case "$ARCH" in
        x86_64|amd64)
            BINARY_NAME="fivenines-agent-linux-amd64"
            ;;
        aarch64|arm64)
            BINARY_NAME="fivenines-agent-linux-arm64"
            ;;
        *)
            exit_with_error "Unsupported architecture: $ARCH"
            ;;
    esac
fi

print_success "Architecture: $ARCH, libc: $LIBC_TYPE"

# Stop the agent if running (skip in test mode)
if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
  echo "Stopping agent..."
  if [ -f "$INSTALL_DIR/stop.sh" ]; then
      "$INSTALL_DIR/stop.sh" 2>/dev/null || true
  else
      pkill -f "$BINARY_NAME" 2>/dev/null || true
  fi
  sleep 1
  print_success "Agent stopped"
else
  print_warning "Skipping agent stop (test mode)"
fi

# Download new version
echo "Downloading latest version..."
TARBALL_NAME="${BINARY_NAME}.tar.gz"

# See make_work_dir: /tmp is world-writable, so the download lands somewhere
# only this process can reach. The CI harness still pre-places a tarball at
# the old path, which is copied in rather than used in place.
PREPLACED_TARBALL="/tmp/${TARBALL_NAME}"
WORK_DIR=$(make_work_dir) || exit_with_error "Failed to create a private temporary directory"
trap 'rm -rf "$WORK_DIR"' EXIT
TARBALL_PATH="${WORK_DIR}/${TARBALL_NAME}"

# Only download_with_fallback sets this; an empty value means the tarball did
# not come from a mirror that publishes a checksum.
DOWNLOAD_SOURCE=""

if [ "${FIVENINES_TEST_MODE:-}" = "1" ] && [ -f "$PREPLACED_TARBALL" ]; then
    print_warning "Using pre-placed tarball at $PREPLACED_TARBALL (test mode)"
    cp "$PREPLACED_TARBALL" "$TARBALL_PATH" || exit_with_error "Failed to stage the pre-placed tarball"
elif [ -n "${FIVENINES_AGENT_URL:-}" ]; then
    print_warning "Using custom agent URL: $FIVENINES_AGENT_URL"
    download_file "$FIVENINES_AGENT_URL" "$TARBALL_PATH" || exit_with_error "Failed to download from custom URL"
    print_success "Downloaded from custom URL"
else
    download_with_fallback "$TARBALL_NAME" "$TARBALL_PATH" || exit_with_error "Download failed"
fi

# Verify before the installed version is moved aside.
if ! verify_agent_tarball "$TARBALL_PATH" "$TARBALL_NAME"; then
    rm -f "$TARBALL_PATH"
    print_error "The previous agent is still installed and was not touched."
    exit_with_error "Refusing to install an unverified agent tarball."
fi

# Backup old version
if [ -d "$INSTALL_DIR/$BINARY_NAME" ]; then
    rm -rf "$INSTALL_DIR/${BINARY_NAME}.old" 2>/dev/null || true
    mv "$INSTALL_DIR/$BINARY_NAME" "$INSTALL_DIR/${BINARY_NAME}.old"
fi

# Extract new version
tar -xzf "$TARBALL_PATH" -C "$INSTALL_DIR" || exit_with_error "Extraction failed"
rm -f "$TARBALL_PATH" 2>/dev/null || true
chmod +x "$INSTALL_DIR/$BINARY_NAME/$BINARY_NAME"
print_success "Updated agent binary"

# Remove backup
rm -rf "$INSTALL_DIR/${BINARY_NAME}.old" 2>/dev/null || true

# Start the agent (skip in test mode)
if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
  echo "Starting agent..."
  if [ -f "$INSTALL_DIR/start.sh" ]; then
      "$INSTALL_DIR/start.sh"
  else
      export CONFIG_DIR="$CONFIG_DIR"
      nohup "$INSTALL_DIR/$BINARY_NAME/$BINARY_NAME" >> "$INSTALL_DIR/agent.log" 2>&1 &
      echo "Agent started (PID: $!)"
  fi

  sleep 2

  if pgrep -f "$BINARY_NAME" > /dev/null; then
      print_success "Agent is running"
  else
      print_warning "Agent may have failed to start. Check: $INSTALL_DIR/logs.sh"
  fi
else
  print_warning "Skipping agent start (test mode)"
fi

echo ""
printf '%b\n' "${GREEN}Update complete!${NC}"
echo ""

# Clean up script
rm -f "$0" 2>/dev/null || true
