#!/bin/bash

# Fivenines Agent User-Level Update Script
# Updates an existing user-level installation
#
# Usage: bash fivenines_update_user.sh

set -e

INSTALL_DIR="${FIVENINES_INSTALL_DIR:-$HOME/.local/fivenines}"
CONFIG_DIR="${FIVENINES_CONFIG_DIR:-$HOME/.config/fivenines_agent}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

function print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

function print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

function print_error() {
    echo -e "${RED}✗${NC} $1"
}

function exit_with_error() {
    print_error "$1"
    exit 1
}

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Fivenines Agent - User-Level Update${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Check if installation exists
if [ ! -d "$INSTALL_DIR" ]; then
    exit_with_error "No installation found at $INSTALL_DIR"
fi

# Check for token
if [ ! -f "$CONFIG_DIR/TOKEN" ]; then
    exit_with_error "Token file not found at $CONFIG_DIR/TOKEN"
fi

print_success "Found existing installation"

# Detect architecture
ARCH=$(uname -m)
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

print_success "Architecture: $ARCH"

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
DOWNLOAD_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/latest/download/${BINARY_NAME}.tar.gz"
TARBALL_PATH="/tmp/${BINARY_NAME}.tar.gz"

if command -v wget &> /dev/null; then
    wget -q --connect-timeout=10 "$DOWNLOAD_URL" -O "$TARBALL_PATH" || exit_with_error "Download failed"
elif command -v curl &> /dev/null; then
    curl -sL --connect-timeout 10 "$DOWNLOAD_URL" -o "$TARBALL_PATH" || exit_with_error "Download failed"
else
    exit_with_error "Neither wget nor curl found"
fi

print_success "Downloaded"

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
echo -e "${GREEN}Update complete!${NC}"
echo ""

# Clean up script
rm -f "$0" 2>/dev/null || true
