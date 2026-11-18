#!/bin/sh

# Fivenines Agent User-Level Uninstall Script
# Removes a user-level installation
#
# Usage: bash fivenines_uninstall_user.sh

INSTALL_DIR="${FIVENINES_INSTALL_DIR:-$HOME/.local/fivenines}"
CONFIG_DIR="${FIVENINES_CONFIG_DIR:-$HOME/.config/fivenines_agent}"

# What fivenines_setup_user.sh and the agent write in the two directories,
# and all this script removes there, with the .env the agent reads and the
# .env.system --from-system leaves: FIVENINES_INSTALL_DIR or
# FIVENINES_CONFIG_DIR may name a directory that holds other files ($HOME/bin,
# $HOME/.config), which rm -rf took with them (#313). The agent directories
# (fivenines-agent-*, the update's .old backup among them) and the agent's
# temporary sudo_refusals.* files are found by name. ci/build-scripts.sh keeps
# both lines equal to fivenines_setup.sh's.
USER_INSTALL_FILES="start.sh stop.sh status.sh logs.sh refresh.sh agent.pid agent.log"
USER_CONFIG_FILES="TOKEN MACHINE_ID last_capture_id journal_units.allow image_inventory_done image_inventory_done.tmp sudo_refusals"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# The message is printed as it is (%s): through %b, a backslash sequence in a
# path it names (a directory another account chose) became an escape.
print_success() {
    printf '%b%s\n' "${GREEN}[+]${NC} " "$1"
}

print_warning() {
    printf '%b%s\n' "${YELLOW}[!]${NC} " "$1"
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

# The installation is found by its start.sh. Without one at INSTALL_DIR (one
# made with FIVENINES_INSTALL_DIR, run here without it), its agent could not
# be stopped nor its @reboot line found, while the default config directory,
# with the TOKEN that agent may be using, would still be deleted: refused.
if [ ! -f "$INSTALL_DIR/start.sh" ]; then
    print_warning "No user-level installation in $INSTALL_DIR (no start.sh)."
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
# A crontab that cannot be read is left as it is: nothing is written.
start_spellings "$INSTALL_DIR" "$HOME"
if CRON_ENTRIES=$(crontab -l 2>/dev/null) \
    && printf '%s\n' "$CRON_ENTRIES" | grep -qF -e "$START_SPELLING_1" -e "$START_SPELLING_2" \
    -e "$START_SPELLING_3" -e "$START_SPELLING_4" -e "$START_SPELLING_5"; then
    echo "Removing crontab entry..."
    printf '%s\n' "$CRON_ENTRIES" | grep -vF -e "$START_SPELLING_1" -e "$START_SPELLING_2" \
        -e "$START_SPELLING_3" -e "$START_SPELLING_4" -e "$START_SPELLING_5" | crontab - 2>/dev/null || true
    print_success "Crontab entry removed"
fi

# Only the files the installers and the agent write, then each directory once
# nothing else is left in it (it holds start.sh, checked above).
echo "Removing the installation's files..."
REMOVE_FAILED=0
for name in $USER_INSTALL_FILES; do
    rm -f -- "${INSTALL_DIR:?}/${name:?}" || REMOVE_FAILED=1
done
for agent_dir in "$INSTALL_DIR"/fivenines-agent-*; do
    if [ -d "$agent_dir" ] && [ ! -L "$agent_dir" ]; then
        rm -rf -- "${agent_dir:?}" || REMOVE_FAILED=1
    fi
done
for name in $USER_CONFIG_FILES .env .env.system; do
    rm -f -- "${CONFIG_DIR:?}/${name:?}" || REMOVE_FAILED=1
done
for name in "$CONFIG_DIR"/sudo_refusals.*; do
    if [ -e "$name" ] || [ -L "$name" ]; then
        rm -f -- "$name" || REMOVE_FAILED=1
    fi
done
for dir in "$INSTALL_DIR" "$CONFIG_DIR"; do
    if [ ! -e "$dir" ]; then
        continue
    fi
    if rmdir -- "$dir" 2>/dev/null; then
        print_success "Removed $dir"
    else
        # Names for a message, at most ten: ls -A lists the dot files too.
        # shellcheck disable=SC2012
        print_warning "Kept $dir: it still holds $(ls -A -- "$dir" 2>/dev/null | head -n 10 | tr '\n' ' ')"
    fi
done
if [ "$REMOVE_FAILED" != "0" ]; then
    print_warning "Some files could not be removed (see above)."
fi

echo ""
printf '%b\n' "${GREEN}Uninstall complete!${NC}"
echo ""

# Clean up script
rm -f "$0" 2>/dev/null || true
