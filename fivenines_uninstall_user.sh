#!/bin/sh

# Fivenines Agent User-Level Uninstall Script
# Removes a user-level installation
#
# Usage: bash fivenines_uninstall_user.sh

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

echo ""
printf '%b\n' "${BLUE}===============================================================${NC}"
printf '%b\n' "${BLUE}  Fivenines Agent - User-Level Uninstall${NC}"
printf '%b\n' "${BLUE}===============================================================${NC}"
echo ""

# Confirm
printf "This will remove the Fivenines agent. Continue? [y/N] "
read REPLY
case "$REPLY" in
    [Yy]*) ;;
    *)
        echo "Cancelled."
        exit 0
        ;;
esac

echo ""

# Stop the agent if running
echo "Stopping agent..."
if [ -f "$INSTALL_DIR/stop.sh" ]; then
    "$INSTALL_DIR/stop.sh" 2>/dev/null || true
fi
pkill -f "fivenines-agent-linux" 2>/dev/null || true
pkill -f "fivenines-agent-alpine" 2>/dev/null || true
sleep 1
print_success "Agent stopped"

# Remove crontab entry if exists
if crontab -l 2>/dev/null | grep -q "fivenines"; then
    echo "Removing crontab entry..."
    crontab -l 2>/dev/null | grep -v "fivenines" | crontab - 2>/dev/null || true
    print_success "Crontab entry removed"
fi

# Remove installation directory
if [ -d "$INSTALL_DIR" ]; then
    echo "Removing installation directory..."
    rm -rf "$INSTALL_DIR"
    print_success "Removed $INSTALL_DIR"
else
    print_warning "Installation directory not found: $INSTALL_DIR"
fi

# Remove config directory
if [ -d "$CONFIG_DIR" ]; then
    echo "Removing config directory..."
    rm -rf "$CONFIG_DIR"
    print_success "Removed $CONFIG_DIR"
else
    print_warning "Config directory not found: $CONFIG_DIR"
fi

echo ""
printf '%b\n' "${GREEN}Uninstall complete!${NC}"
echo ""

# Clean up script
rm -f "$0" 2>/dev/null || true
