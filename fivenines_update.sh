#!/bin/sh
# This script is used to update the fivenines agent
#
# Environment variables:
#   FIVENINES_AGENT_URL    - Custom download URL for the agent tarball (e.g., pre-release
#                            builds). Unverified unless FIVENINES_AGENT_SHA256 is also set.
#   FIVENINES_AGENT_SHA256 - Expected SHA-256 of the tarball. Overrides the published
#                            SHA256SUMS; the only way to verify a custom URL.
#   FIVENINES_SKIP_VERIFY  - Set to 1 to install WITHOUT verifying the tarball. Unsupported.
#   FIVENINES_REQUIRE_SIGNATURE - Set to 1 to abort unless the release signature over
#                            SHA256SUMS verifies (default: warn and fall back to the checksum).
#
# Example with custom build:
#   FIVENINES_AGENT_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/download/feature-branch-abc1234/fivenines-agent-linux-amd64.tar.gz" bash fivenines_update.sh

# Mirror URLs (R2 is IPv6-compatible, GitHub is fallback)
R2_BASE_URL="https://releases.fivenines.io/latest"
GITHUB_RELEASES_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/latest/download"
GITHUB_RAW_URL="https://raw.githubusercontent.com/Five-Nines-io/fivenines_agent/main"

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
    exit 1
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
# The matching PRIVATE key lives only in the RELEASE_SIGNING_KEY repository
# secret - never in the release bucket - which is what makes this worth
# anything: a mirror that rewrites SHA256SUMS cannot re-sign it.
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

  wget -T 10 -q "$url" -O "$output" 2>/dev/null
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

detect_system() {
  if command -v rc-service >/dev/null 2>&1 && [ -d "/etc/init.d" ]; then
    echo "openrc"
  elif command -v systemctl >/dev/null 2>&1 && [ -d "/etc/systemd/system" ]; then
    echo "systemd"
  else
    echo "unknown"
  fi
}

# Test mode: skip network calls and service management for CI testing
if [ "${FIVENINES_TEST_MODE:-}" = "1" ]; then
  print_warning "WARNING: Test mode enabled - skipping network checks and service management"
fi

# Print banner
echo ""
printf '%b\n' "${BLUE}===============================================================${NC}"
printf '%b\n' "${BLUE}  Fivenines Agent - System Update${NC}"
printf '%b\n' "${BLUE}===============================================================${NC}"
echo ""

# Detect system type
SYSTEM_TYPE=$(detect_system)

# stop the agent (skip in test mode)
if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
  print_warning "Stopping fivenines-agent service..."
  if [ "$SYSTEM_TYPE" = "openrc" ]; then
    rc-service fivenines-agent stop 2>/dev/null || true
  else
    systemctl stop fivenines-agent.service
  fi
  print_success "Agent stopped"
else
  print_warning "Skipping service stop (test mode)"
fi

# if the home directory of user "fivenines" is /home/fivenines (which is the old location), migrate user's home directory to /opt/fivenines
if [ "$(getent passwd fivenines | cut -d: -f6)" = "/home/fivenines" ]; then
        print_warning "Migrating fivenines.io's working directory from /home/fivenines to /opt/fivenines"
        # if /opt/fivenines exists, or /home/fivenines not exists, exit
        if [ -d /opt/fivenines ] || [ ! -d /home/fivenines ]; then
                exit_with_error "/opt/fivenines already exists or /home/fivenines does not exist"
        fi
        usermod -m -d /opt/fivenines fivenines
        print_success "Working directory migrated to /opt/fivenines"
fi

# Check if the package is installed
if ! su - fivenines -s /bin/bash -c 'pipx list | grep -q fivenines_agent'; then
        print_success "Agent is not installed with pipx. No need to clean the old package."
else
        print_warning "Uninstalling the old fivenines_agent package"
        su - fivenines -s /bin/bash -c 'python3 -m pipx uninstall fivenines_agent'
fi

CURRENT_ARCH=$(uname -m)
INSTALL_DIR="/opt/fivenines"

# Update the agent based on the architecture and libc
LIBC_TYPE=$(detect_libc)
print_success "Detected architecture: $CURRENT_ARCH"
print_success "Detected libc: $LIBC_TYPE"
if [ "$LIBC_TYPE" = "musl" ]; then
        if [ "$CURRENT_ARCH" = "aarch64" ]; then
                BINARY_NAME="fivenines-agent-alpine-arm64"
        else
                BINARY_NAME="fivenines-agent-alpine-amd64"
        fi
else
        if [ "$CURRENT_ARCH" = "aarch64" ]; then
                BINARY_NAME="fivenines-agent-linux-arm64"
        else
                BINARY_NAME="fivenines-agent-linux-amd64"
        fi
fi

TARBALL_NAME="${BINARY_NAME}.tar.gz"

# The CI harness pre-places a tarball at the old, predictable path; it is
# copied into the private work directory rather than used in place, so the
# verified-then-extracted file is one nothing else can swap underneath us.
PREPLACED_TARBALL="/tmp/${TARBALL_NAME}"
WORK_DIR=$(make_work_dir) || exit_with_error "Failed to create a private temporary directory"
trap 'rm -rf "$WORK_DIR"' EXIT
TARBALL_PATH="${WORK_DIR}/${TARBALL_NAME}"
AGENT_DIR="${INSTALL_DIR}/${BINARY_NAME}"
AGENT_EXECUTABLE="${AGENT_DIR}/${BINARY_NAME}"

# Only download_with_fallback sets this; an empty value means the tarball did
# not come from a mirror that publishes a checksum.
DOWNLOAD_SOURCE=""

if [ "${FIVENINES_TEST_MODE:-}" = "1" ] && [ -f "$PREPLACED_TARBALL" ]; then
    print_warning "Using pre-placed tarball at $PREPLACED_TARBALL (test mode)"
    cp "$PREPLACED_TARBALL" "$TARBALL_PATH" || exit_with_error "Failed to stage the pre-placed tarball"
elif [ -n "${FIVENINES_AGENT_URL:-}" ]; then
    print_warning "Using custom agent URL: $FIVENINES_AGENT_URL"
    wget -T 10 -q "$FIVENINES_AGENT_URL" -O "$TARBALL_PATH" || exit_with_error "Failed to download from custom URL"
    print_success "Downloaded from custom URL"
else
    download_with_fallback "$TARBALL_NAME" "$TARBALL_PATH" "${GITHUB_RELEASES_URL}/${TARBALL_NAME}" || exit_with_error "Failed to download agent"
fi

# Verify before the running installation is removed. The service is already
# stopped at this point, so an abort here has to tell the operator how to get
# the agent they still have back up.
if ! verify_agent_tarball "$TARBALL_PATH" "$TARBALL_NAME"; then
    rm -f "$TARBALL_PATH"
    print_error "The previous agent is still installed and was not touched."
    if [ "$SYSTEM_TYPE" = "openrc" ]; then
        print_error "Restart it with: rc-service fivenines-agent start"
    else
        print_error "Restart it with: systemctl start fivenines-agent"
    fi
    exit_with_error "Refusing to install an unverified agent tarball."
fi

# Remove old installation if it exists
if [ -d "$AGENT_DIR" ]; then
        print_warning "Removing previous installation..."
        rm -rf "$AGENT_DIR"
fi

# Also remove old single-binary format if present
if [ -f "${INSTALL_DIR}/fivenines_agent" ]; then
        print_warning "Removing old single-binary installation..."
        rm -f "${INSTALL_DIR}/fivenines_agent"
fi

# Extract the tarball
print_warning "Extracting agent to $INSTALL_DIR..."
tar -xzf "$TARBALL_PATH" -C "$INSTALL_DIR" || exit_with_error "Failed to extract agent"

# Clean up the tarball
rm -f "$TARBALL_PATH"

# Verify extraction was successful
if [ ! -f "$AGENT_EXECUTABLE" ]; then
        exit_with_error "Agent executable not found after extraction at $AGENT_EXECUTABLE"
fi

# Create/update symlink at a fixed path for the systemd service
ln -sf "$AGENT_EXECUTABLE" "${INSTALL_DIR}/fivenines_agent"

# Remove old wrapper script if it exists
rm -f "${INSTALL_DIR}/run_agent.sh"

# Set permissions
chown -R fivenines:fivenines "$INSTALL_DIR"
chmod -R 755 "$AGENT_DIR"

# Heal installs set up before the config dir was owned by the agent user:
# without ownership of /etc/fivenines_agent the agent can never persist
# MACHINE_ID, so a reinstall on such a box enrolls a duplicate host.
if [ -d /etc/fivenines_agent ]; then
        chown fivenines:fivenines /etc/fivenines_agent
        chmod 750 /etc/fivenines_agent
fi

# CloudLinux: ensure fivenines is in clsupergid group for proper permissions
if [ -f "/etc/cloudlinux-release" ]; then
        print_success "CloudLinux detected"
        if getent group clsupergid >/dev/null 2>&1; then
                if ! id -nG fivenines | grep -qw clsupergid; then
                        print_success "Adding fivenines user to clsupergid group"
                        usermod -a -G clsupergid fivenines
                fi
        fi
fi

print_success "Agent updated successfully at $AGENT_DIR"

# Restore SELinux file contexts after extraction (no-op if SELinux is not active)
if command -v restorecon >/dev/null 2>&1; then
  restorecon -Rv "$INSTALL_DIR" 2>/dev/null || true
fi

# Update service file and restart (skip in test mode)
if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
  print_warning "Updating the service file..."
  if [ "$SYSTEM_TYPE" = "openrc" ]; then
    download_with_fallback "fivenines-agent.openrc" "/etc/init.d/fivenines-agent" "${GITHUB_RAW_URL}/fivenines-agent.openrc"
    chmod 755 /etc/init.d/fivenines-agent
  else
    download_with_fallback "fivenines-agent.service" "/etc/systemd/system/fivenines-agent.service" "${GITHUB_RAW_URL}/fivenines-agent.service"
    print_warning "Reloading the systemd daemon..."
    systemctl daemon-reload
  fi

  # Restart the agent
  print_warning "Restarting fivenines-agent service..."
  if [ "$SYSTEM_TYPE" = "openrc" ]; then
    rc-service fivenines-agent restart
  else
    systemctl restart fivenines-agent.service
  fi
  print_success "Agent restarted"
else
  print_warning "Skipping service file update and restart (test mode)"
fi

echo ""
printf '%b\n' "${BLUE}===============================================================${NC}"
printf '%b\n' "${BLUE}  Update Complete!${NC}"
printf '%b\n' "${BLUE}===============================================================${NC}"
echo ""

# Remove the update script
rm -f fivenines_update.sh 2>/dev/null || true
