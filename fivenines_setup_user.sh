#!/bin/sh

# Fivenines Agent User-Level Setup Script
# For environments without root access (shared hosting, managed VPS, etc.)
#
# Usage: bash fivenines_setup_user.sh YOUR_TOKEN
#
# Environment variables:
#   FIVENINES_AGENT_URL    - Custom download URL for the agent tarball (e.g., feature branch builds).
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

detect_architecture() {
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
    print_success "Architecture: $ARCH, libc: $LIBC_TYPE ($BINARY_NAME)"
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

download_agent() {
    echo "Downloading agent..."

    tarball_name="${BINARY_NAME}.tar.gz"
    tarball_path="/tmp/${tarball_name}"

    # Only download_with_fallback sets this; an empty value means the tarball
    # did not come from a mirror that publishes a checksum.
    DOWNLOAD_SOURCE=""

    # Use custom URL if provided, otherwise use fallback mechanism
    if [ "${FIVENINES_TEST_MODE:-}" = "1" ] && [ -f "$tarball_path" ]; then
        print_warning "Using pre-placed tarball at $tarball_path (test mode)"
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

    # Create stop script
    cat > "$INSTALL_DIR/stop.sh" << EOF
#!/bin/bash
# Stop the Fivenines agent
if [ -f "$INSTALL_DIR/agent.pid" ]; then
    PID=\$(cat "$INSTALL_DIR/agent.pid")
    if kill -0 "\$PID" 2>/dev/null; then
        kill "\$PID"
        rm -f "$INSTALL_DIR/agent.pid"
        echo "Agent stopped (PID: \$PID)"
    else
        echo "Agent not running (stale PID file)"
        rm -f "$INSTALL_DIR/agent.pid"
    fi
else
    # Try to find by process name
    PID=\$(pgrep -f "$BINARY_NAME" 2>/dev/null | head -1)
    if [ -n "\$PID" ]; then
        kill "\$PID"
        echo "Agent stopped (PID: \$PID)"
    else
        echo "Agent not running"
    fi
fi
EOF
    chmod +x "$INSTALL_DIR/stop.sh"
    print_success "Created stop.sh"

    # Create status script
    cat > "$INSTALL_DIR/status.sh" << EOF
#!/bin/bash
# Check Fivenines agent status
PID=\$(pgrep -f "$BINARY_NAME" 2>/dev/null | head -1)
if [ -n "\$PID" ]; then
    echo "Agent is running (PID: \$PID)"
    echo "Log file: $LOG_FILE"
    echo ""
    echo "Last 10 log lines:"
    tail -10 "$LOG_FILE" 2>/dev/null || echo "(no log yet)"
else
    echo "Agent is not running"
fi
EOF
    chmod +x "$INSTALL_DIR/status.sh"
    print_success "Created status.sh"

    # Create logs script
    cat > "$INSTALL_DIR/logs.sh" << EOF
#!/bin/bash
# View Fivenines agent logs
tail -f "$LOG_FILE"
EOF
    chmod +x "$INSTALL_DIR/logs.sh"
    print_success "Created logs.sh"

    # Create refresh script (SIGHUP)
    cat > "$INSTALL_DIR/refresh.sh" << EOF
#!/bin/bash
# Refresh agent capabilities (after permission changes)
PID=\$(pgrep -f "$BINARY_NAME" 2>/dev/null | head -1)
if [ -n "\$PID" ]; then
    kill -HUP "\$PID"
    echo "Sent SIGHUP to agent (PID: \$PID) - capabilities will refresh"
else
    echo "Agent is not running"
fi
EOF
    chmod +x "$INSTALL_DIR/refresh.sh"
    print_success "Created refresh.sh"

    echo ""
}

start_agent() {
    echo "Starting agent..."

    "$INSTALL_DIR/start.sh"

    # Wait a moment and check if it's running
    sleep 2

    if pgrep -f "$BINARY_NAME" > /dev/null; then
        print_success "Agent is running"
    else
        print_warning "Agent may have failed to start. Check logs:"
        echo "  $INSTALL_DIR/logs.sh"
    fi

    echo ""
}

print_crontab_instructions() {
    printf '%b\n' "${BLUE}===============================================================${NC}"
    printf '%b\n' "${BLUE}  Auto-Start on Reboot (Optional)${NC}"
    printf '%b\n' "${BLUE}===============================================================${NC}"
    echo ""
    echo "To automatically start the agent when your server reboots,"
    echo "add this line to your crontab (run: crontab -e):"
    echo ""
    printf '%b\n' "${GREEN}@reboot $INSTALL_DIR/start.sh${NC}"
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
    print_crontab_instructions
    printf '%b\n' "${YELLOW}Note:${NC} Some features (SMART, RAID) are unavailable without sudo."
    echo ""
    echo "Happy monitoring!"
    echo ""
}

# Test mode: skip network calls and service management for CI testing
if [ "${FIVENINES_TEST_MODE:-}" = "1" ]; then
  print_warning "WARNING: Test mode enabled - skipping network checks and agent startup"
fi

# Main execution
print_banner

# Check token argument
if [ $# -eq 0 ]; then
    echo "Usage: bash $0 YOUR_TOKEN"
    echo ""
    echo "Get your token from https://fivenines.io"
    exit 1
fi

TOKEN="$1"

# Validate token format (basic check)
if [ ${#TOKEN} -lt 10 ]; then
    exit_with_error "Token seems too short. Please check your token."
fi

check_requirements
detect_architecture
create_directories
save_token "$TOKEN"
if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
  test_connectivity
else
  print_warning "Skipping connectivity test (test mode)"
fi
download_agent
create_run_script
if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
  start_agent
else
  print_warning "Skipping agent startup (test mode)"
fi
print_final_instructions

# Clean up script
rm -f "$0" 2>/dev/null || true
