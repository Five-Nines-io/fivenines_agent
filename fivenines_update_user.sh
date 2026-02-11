#!/bin/sh

# Fivenines Agent User-Level Update Script
# Updates an existing user-level installation
#
# Usage: bash fivenines_update_user.sh
#
# Environment variables:
#   FIVENINES_AGENT_URL   - Custom download URL for the agent tarball (e.g., pre-release builds)
#   FIVENINES_INSTALL_DIR - Custom install directory (default: ~/.local/fivenines)
#   FIVENINES_CONFIG_DIR  - Custom config directory (default: ~/.config/fivenines_agent)
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
    local url="$1"
    local output="$2"

    if command -v wget > /dev/null 2>&1; then
        wget -q -T 10 "$url" -O "$output"
    elif command -v curl > /dev/null 2>&1; then
        curl -sL --connect-timeout 10 "$url" -o "$output"
    else
        return 1
    fi
}

download_with_fallback() {
    local filename="$1"
    local output="$2"
    local r2_url="${R2_BASE_URL}/${filename}"
    local github_url="${GITHUB_RELEASES_URL}/${filename}"

    # Try R2 first (IPv6 compatible)
    if download_file "$r2_url" "$output" 2>/dev/null; then
        print_success "Downloaded from releases.fivenines.io"
        return 0
    fi

    # Fallback to GitHub
    print_warning "R2 mirror unavailable, trying GitHub..."
    if download_file "$github_url" "$output" 2>/dev/null; then
        print_success "Downloaded from GitHub"
        return 0
    fi

    return 1
}

detect_libc() {
    if ldd --version 2>&1 | grep -qi musl; then
        echo "musl"
    elif [ -f "/lib/ld-musl-x86_64.so.1" ] || [ -f "/lib/ld-musl-aarch64.so.1" ]; then
        echo "musl"
    else
        echo "glibc"
    fi
}

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

# Stop the agent if running
echo "Stopping agent..."
if [ -f "$INSTALL_DIR/stop.sh" ]; then
    "$INSTALL_DIR/stop.sh" 2>/dev/null || true
else
    pkill -f "$BINARY_NAME" 2>/dev/null || true
fi
sleep 1
print_success "Agent stopped"

# Download new version
echo "Downloading latest version..."
TARBALL_NAME="${BINARY_NAME}.tar.gz"
TARBALL_PATH="/tmp/${TARBALL_NAME}"

if [ -n "${FIVENINES_AGENT_URL:-}" ]; then
    print_warning "Using custom agent URL: $FIVENINES_AGENT_URL"
    download_file "$FIVENINES_AGENT_URL" "$TARBALL_PATH" || exit_with_error "Failed to download from custom URL"
    print_success "Downloaded from custom URL"
else
    download_with_fallback "$TARBALL_NAME" "$TARBALL_PATH" || exit_with_error "Download failed"
fi

# Backup old version
if [ -d "$INSTALL_DIR/$BINARY_NAME" ]; then
    rm -rf "$INSTALL_DIR/${BINARY_NAME}.old" 2>/dev/null || true
    mv "$INSTALL_DIR/$BINARY_NAME" "$INSTALL_DIR/${BINARY_NAME}.old"
fi

# Extract new version
tar -xzf "$TARBALL_PATH" -C "$INSTALL_DIR" || exit_with_error "Extraction failed"
rm -f "$TARBALL_PATH"
chmod +x "$INSTALL_DIR/$BINARY_NAME/$BINARY_NAME"
print_success "Updated agent binary"

# Remove backup
rm -rf "$INSTALL_DIR/${BINARY_NAME}.old" 2>/dev/null || true

# Start the agent
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

echo ""
printf '%b\n' "${GREEN}Update complete!${NC}"
echo ""

# Clean up script
rm -f "$0" 2>/dev/null || true
