#!/bin/bash

# Fivenines Agent User-Level Setup Script
# For environments without root access (shared hosting, managed VPS, etc.)
#
# Usage: bash fivenines_setup_user.sh YOUR_TOKEN
#
# Environment variables:
#   FIVENINES_AGENT_URL   - Custom download URL for the agent tarball (e.g., feature branch builds)
#   FIVENINES_INSTALL_DIR - Custom install directory (default: ~/.local/fivenines)
#   FIVENINES_CONFIG_DIR  - Custom config directory (default: ~/.config/fivenines_agent)
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

function print_banner() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Fivenines Agent - User-Level Installation${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

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
    echo ""
    echo "For assistance, contact: sebastien@fivenines.io"
    exit 1
}

function check_requirements() {
    echo "Checking requirements..."

    # Check for wget or curl
    if command -v wget &> /dev/null; then
        DOWNLOADER="wget"
        print_success "wget available"
    elif command -v curl &> /dev/null; then
        DOWNLOADER="curl"
        print_success "curl available"
    else
        exit_with_error "Neither wget nor curl found. Please install one of them."
    fi

    # Check for tar
    if ! command -v tar &> /dev/null; then
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

function download_file() {
    local url="$1"
    local output="$2"

    if [ "$DOWNLOADER" = "wget" ]; then
        wget -q --connect-timeout=10 "$url" -O "$output"
    else
        curl -sL --connect-timeout 10 "$url" -o "$output"
    fi
}

function download_with_fallback() {
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

function detect_architecture() {
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
    print_success "Architecture: $ARCH ($BINARY_NAME)"
}

function create_directories() {
    echo "Creating directories..."

    mkdir -p "$INSTALL_DIR"
    print_success "Install directory: $INSTALL_DIR"

    mkdir -p "$CONFIG_DIR"
    print_success "Config directory: $CONFIG_DIR"

    echo ""
}

function save_token() {
    local token="$1"

    echo "Saving token..."
    echo -n "$token" > "$CONFIG_DIR/TOKEN"
    chmod 600 "$CONFIG_DIR/TOKEN"
    print_success "Token saved securely"
    echo ""
}

function download_agent() {
    echo "Downloading agent..."

    local tarball_name="${BINARY_NAME}.tar.gz"
    local tarball_path="/tmp/${tarball_name}"

    # Remove old installation if exists
    if [ -d "$INSTALL_DIR/$BINARY_NAME" ]; then
        rm -rf "$INSTALL_DIR/$BINARY_NAME"
    fi

    # Use custom URL if provided, otherwise use fallback mechanism
    if [ -n "${FIVENINES_AGENT_URL:-}" ]; then
        print_warning "Using custom agent URL: $FIVENINES_AGENT_URL"
        download_file "$FIVENINES_AGENT_URL" "$tarball_path" || exit_with_error "Failed to download agent from custom URL"
        print_success "Downloaded from custom URL"
    else
        download_with_fallback "$tarball_name" "$tarball_path" || exit_with_error "Failed to download agent"
    fi

    tar -xzf "$tarball_path" -C "$INSTALL_DIR" || exit_with_error "Failed to extract agent"
    print_success "Extracted to $INSTALL_DIR"

    rm -f "$tarball_path"

    # Make executable
    chmod +x "$INSTALL_DIR/$BINARY_NAME/$BINARY_NAME"
    print_success "Agent installed"

    echo ""
}

function test_connectivity() {
    echo "Testing connectivity..."

    local hosts=("api.fivenines.io" "eu.fivenines.io" "us.fivenines.io")
    local connected=false

    for host in "${hosts[@]}"; do
        if ping -c 1 -W 3 "$host" &> /dev/null 2>&1; then
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

function create_run_script() {
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

function start_agent() {
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

function print_crontab_instructions() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Auto-Start on Reboot (Optional)${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "To automatically start the agent when your server reboots,"
    echo "add this line to your crontab (run: crontab -e):"
    echo ""
    echo -e "${GREEN}@reboot $INSTALL_DIR/start.sh${NC}"
    echo ""
}

function print_final_instructions() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Installation Complete!${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Management commands:"
    echo "  $INSTALL_DIR/start.sh    - Start the agent"
    echo "  $INSTALL_DIR/stop.sh     - Stop the agent"
    echo "  $INSTALL_DIR/status.sh   - Check agent status"
    echo "  $INSTALL_DIR/logs.sh     - View agent logs"
    echo "  $INSTALL_DIR/refresh.sh  - Refresh capabilities (after permission changes)"
    echo ""
    print_crontab_instructions
    echo -e "${YELLOW}Note:${NC} Some features (SMART, RAID) are unavailable without sudo."
    echo ""
    echo "Happy monitoring!"
    echo ""
}

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
test_connectivity
download_agent
create_run_script
start_agent
print_final_instructions

# Clean up script
rm -f "$0" 2>/dev/null || true
