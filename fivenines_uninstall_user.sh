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

# The installation is found by its start.sh. Without one at INSTALL_DIR (one
# made with FIVENINES_INSTALL_DIR, run here without it), its agent could not
# be stopped nor its @reboot line found, while the default config directory,
# with the TOKEN that agent may be using, would still be deleted: refused.
if [ ! -f "$INSTALL_DIR/start.sh" ]; then
    printf '%b\n' "${YELLOW}[!]${NC} No user-level installation in $INSTALL_DIR (no start.sh)."
    echo "If it was installed with FIVENINES_INSTALL_DIR or FIVENINES_CONFIG_DIR, run this again with the same values."
    echo "To remove what is left of one whose directory is already gone, delete $CONFIG_DIR yourself."
    exit 1
fi

# Test mode: skip interactive confirmation for CI testing
if [ "${FIVENINES_TEST_MODE:-}" = "1" ]; then
  print_warning "WARNING: Test mode enabled - skipping confirmation prompt"
fi

echo ""
printf '%b\n' "${BLUE}===============================================================${NC}"
printf '%b\n' "${BLUE}  Fivenines Agent - User-Level Uninstall${NC}"
printf '%b\n' "${BLUE}===============================================================${NC}"
echo ""

# Confirm (skip in test mode)
if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
  printf "This will remove the Fivenines agent. Continue? [y/N] "
  read -r REPLY
  case "$REPLY" in
      [Yy]*) ;;
      *)
          echo "Cancelled."
          exit 0
          ;;
  esac
fi

echo ""

# Stop the agent if running (skip in test mode)
if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
  echo "Stopping agent..."
  if [ -f "$INSTALL_DIR/stop.sh" ]; then
      "$INSTALL_DIR/stop.sh" 2>/dev/null || true
  fi
  # Only this installation's agent: the binary name alone also matched any
  # shell or tail -f naming it.
  pkill -f "$(agent_pattern "$INSTALL_DIR")" 2>/dev/null || true
  sleep 1
  print_success "Agent stopped"
else
  print_warning "Skipping agent stop (test mode)"
fi

# Remove the crontab line that starts this installation, however it spells
# start.sh's path (start_spellings), and only that line: matching "fivenines"
# anywhere also removed the user's own lines that merely mentioned it.
start_spellings "$INSTALL_DIR" "$HOME"
CRON_ENTRIES=$(crontab -l 2>/dev/null || true)
if printf '%s\n' "$CRON_ENTRIES" | grep -qF -e "$START_SPELLING_1" -e "$START_SPELLING_2" \
    -e "$START_SPELLING_3" -e "$START_SPELLING_4"; then
    echo "Removing crontab entry..."
    printf '%s\n' "$CRON_ENTRIES" | grep -vF -e "$START_SPELLING_1" -e "$START_SPELLING_2" \
        -e "$START_SPELLING_3" -e "$START_SPELLING_4" | crontab - 2>/dev/null || true
    print_success "Crontab entry removed"
fi

# Remove installation directory (it holds start.sh, checked above)
echo "Removing installation directory..."
rm -rf "$INSTALL_DIR"
print_success "Removed $INSTALL_DIR"

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
