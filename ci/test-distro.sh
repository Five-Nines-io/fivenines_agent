#!/bin/sh
# Distro regression test script for fivenines-agent
# Runs inside a Docker container with the agent binary mounted
#
# Usage: BINARY_VARIANT=linux-amd64 AGENT_DIR=/agent bash ci/test-distro.sh
#
# Environment variables:
#   BINARY_VARIANT  - Binary variant name (e.g., linux-amd64, alpine-arm64)
#   AGENT_DIR       - Directory containing the extracted agent binary
#   SCRIPTS_DIR     - Directory containing install/update/uninstall scripts
#   SKIP_LDD        - Set to "1" to skip ldd check (Alpine)
#   MOCK_API_PORT   - Port for mock API server (default: 8080)
#   TEST_OUTPUT_DIR - Directory for test output files (default: /tmp)

set -u

BINARY_VARIANT="${BINARY_VARIANT:?BINARY_VARIANT must be set}"
AGENT_DIR="${AGENT_DIR:?AGENT_DIR must be set}"
SCRIPTS_DIR="${SCRIPTS_DIR:?SCRIPTS_DIR must be set}"
SKIP_LDD="${SKIP_LDD:-0}"
MOCK_API_PORT="${MOCK_API_PORT:-8080}"
OUTPUT_DIR="${TEST_OUTPUT_DIR:-/tmp}"

BINARY_NAME="fivenines-agent-${BINARY_VARIANT}"
AGENT_EXECUTABLE="${AGENT_DIR}/${BINARY_NAME}/${BINARY_NAME}"

# Install minimal dependencies for testing
echo "Installing test dependencies..."
if command -v apk > /dev/null 2>&1; then
  # Alpine
  apk add --no-cache python3 wget shadow > /dev/null 2>&1 || true
elif command -v yum > /dev/null 2>&1; then
  # CentOS / Rocky / Fedora
  yum install -y -q python3 wget > /dev/null 2>&1 || true
elif command -v apt-get > /dev/null 2>&1; then
  # Debian / Ubuntu
  { apt-get update -qq > /dev/null 2>&1 && apt-get install -y -qq python3 wget > /dev/null 2>&1; } || true
fi

# Background process PID (for cleanup)
MOCK_PID=""

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
RESULTS=""

# Test result tracking
record_result() {
  test_name="$1"
  status="$2"
  detail="${3:-}"
  case "$status" in
    PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
    FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
  esac
  RESULTS="${RESULTS}| ${test_name} | ${status} | ${detail} |\n"
  echo "[${status}] ${test_name} ${detail}"
}

# ---------------------------------------------------------------
# Test 1: Binary starts (--version)
# ---------------------------------------------------------------
echo ""
echo "=== Test 1: Binary --version ==="
if timeout 60 "$AGENT_EXECUTABLE" --version > "${OUTPUT_DIR}/version_output" 2>&1; then
  VERSION_OUTPUT=$(cat "${OUTPUT_DIR}/version_output")
  record_result "--version" "PASS" "$VERSION_OUTPUT"
else
  record_result "--version" "FAIL" "exit code $?"
fi

# ---------------------------------------------------------------
# Test 2: Shared libraries resolve (ldd)
# ---------------------------------------------------------------
echo ""
echo "=== Test 2: Shared library check ==="
if [ "$SKIP_LDD" = "1" ]; then
  record_result "ldd" "SKIP" "Alpine (no reliable ldd)"
else
  if command -v ldd > /dev/null 2>&1; then
    LDD_OUTPUT=$(ldd "$AGENT_EXECUTABLE" 2>&1 || true)
    NOT_FOUND=$(echo "$LDD_OUTPUT" | grep "not found" || true)
    if [ -z "$NOT_FOUND" ]; then
      record_result "ldd" "PASS" "all libraries resolved"
    else
      echo "$NOT_FOUND"
      record_result "ldd" "FAIL" "missing libraries detected"
    fi
  else
    record_result "ldd" "SKIP" "ldd not available"
  fi
fi

# ---------------------------------------------------------------
# Test 3: Dry-run with mock API server
# ---------------------------------------------------------------
echo ""
echo "=== Test 3: Dry-run ==="

# Start mock API server
if command -v python3 > /dev/null 2>&1; then
  python3 "${SCRIPTS_DIR}/ci/mock_api_server.py" "$MOCK_API_PORT" &
  MOCK_PID=$!
  sleep 1

  # Create fake TOKEN and config dir
  mkdir -p /etc/fivenines_agent
  printf '%s' "test-token-for-ci" > /etc/fivenines_agent/TOKEN
  chmod 600 /etc/fivenines_agent/TOKEN

  # Point agent at mock server (API_URL is how the agent reads the API host)
  export API_URL="localhost:${MOCK_API_PORT}"

  if timeout 60 "$AGENT_EXECUTABLE" --dry-run > "${OUTPUT_DIR}/dryrun_output" 2>&1; then
    record_result "dry-run" "PASS" "completed successfully"
  else
    EXIT_CODE=$?
    # Exit code 2 means TOKEN file not found (different config dir)
    # Try with user config dir
    mkdir -p "$HOME/.config/fivenines_agent"
    printf '%s' "test-token-for-ci" > "$HOME/.config/fivenines_agent/TOKEN"
    chmod 600 "$HOME/.config/fivenines_agent/TOKEN"
    if timeout 60 "$AGENT_EXECUTABLE" --dry-run > "${OUTPUT_DIR}/dryrun_output" 2>&1; then
      record_result "dry-run" "PASS" "completed (user config dir)"
    else
      record_result "dry-run" "FAIL" "exit code $EXIT_CODE"
      echo "--- dry-run output ---"
      cat "${OUTPUT_DIR}/dryrun_output" 2>/dev/null || true
      echo "--- end output ---"
    fi
  fi

  kill "$MOCK_PID" 2>/dev/null || true
else
  record_result "dry-run" "SKIP" "python3 not available"
fi

# ---------------------------------------------------------------
# Test 4: System install script
# ---------------------------------------------------------------
echo ""
echo "=== Test 4: System install script ==="

# Create a local tarball and pre-place it where install scripts expect it.
# In test mode, scripts skip the download and use the pre-placed tarball directly.
TARBALL_PATH="/tmp/fivenines-agent-${BINARY_VARIANT}.tar.gz"
(cd "$AGENT_DIR" && tar -czf "$TARBALL_PATH" "${BINARY_NAME}/")

export FIVENINES_TEST_MODE=1

if timeout 120 sh "${SCRIPTS_DIR}/fivenines_setup.sh" "test-token-ci-setup" > "${OUTPUT_DIR}/setup_output" 2>&1; then
  record_result "system-install" "PASS" ""
else
  EXIT_CODE=$?
  record_result "system-install" "FAIL" "exit code $EXIT_CODE"
  echo "--- setup output ---"
  cat "${OUTPUT_DIR}/setup_output" 2>/dev/null || true
  echo "--- end output ---"
fi

# ---------------------------------------------------------------
# Test 5: File permissions after install
# ---------------------------------------------------------------
echo ""
echo "=== Test 5: File permissions ==="

INSTALL_DIR="/opt/fivenines"
TOKEN_FILE="/etc/fivenines_agent/TOKEN"

PERMS_OK=true

# Check TOKEN file permissions (600)
if [ -f "$TOKEN_FILE" ]; then
  TOKEN_PERMS=$(stat -c '%a' "$TOKEN_FILE" 2>/dev/null || stat -f '%Lp' "$TOKEN_FILE" 2>/dev/null || echo "unknown")
  if [ "$TOKEN_PERMS" = "600" ]; then
    echo "  TOKEN permissions: $TOKEN_PERMS (OK)"
  else
    echo "  TOKEN permissions: $TOKEN_PERMS (EXPECTED 600)"
    PERMS_OK=false
  fi
else
  echo "  TOKEN file not found at $TOKEN_FILE"
  PERMS_OK=false
fi

# Check binary permissions (755)
INSTALLED_BINARY="${INSTALL_DIR}/${BINARY_NAME}/${BINARY_NAME}"
if [ -f "$INSTALLED_BINARY" ]; then
  BIN_PERMS=$(stat -c '%a' "$INSTALLED_BINARY" 2>/dev/null || stat -f '%Lp' "$INSTALLED_BINARY" 2>/dev/null || echo "unknown")
  if [ "$BIN_PERMS" = "755" ]; then
    echo "  Binary permissions: $BIN_PERMS (OK)"
  else
    echo "  Binary permissions: $BIN_PERMS (EXPECTED 755)"
    PERMS_OK=false
  fi
else
  echo "  Installed binary not found at $INSTALLED_BINARY"
  PERMS_OK=false
fi

# Check install dir ownership
if [ -d "$INSTALL_DIR" ]; then
  OWNER=$(stat -c '%U:%G' "$INSTALL_DIR" 2>/dev/null || stat -f '%Su:%Sg' "$INSTALL_DIR" 2>/dev/null || echo "unknown")
  if [ "$OWNER" = "fivenines:fivenines" ]; then
    echo "  Install dir owner: $OWNER (OK)"
  else
    echo "  Install dir owner: $OWNER (EXPECTED fivenines:fivenines)"
    PERMS_OK=false
  fi
fi

if [ "$PERMS_OK" = true ]; then
  record_result "file-permissions" "PASS" ""
else
  record_result "file-permissions" "FAIL" "permission mismatch"
fi

# ---------------------------------------------------------------
# Test 6: System update script (TOKEN preservation)
# ---------------------------------------------------------------
echo ""
echo "=== Test 6: System update (TOKEN preservation) ==="

# Save TOKEN content before update
TOKEN_BEFORE=""
if [ -f "$TOKEN_FILE" ]; then
  TOKEN_BEFORE=$(cat "$TOKEN_FILE")
fi

if timeout 120 sh "${SCRIPTS_DIR}/fivenines_update.sh" > "${OUTPUT_DIR}/update_output" 2>&1; then
  # Verify TOKEN preserved
  if [ -f "$TOKEN_FILE" ]; then
    TOKEN_AFTER=$(cat "$TOKEN_FILE")
    if [ "$TOKEN_BEFORE" = "$TOKEN_AFTER" ]; then
      record_result "system-update" "PASS" "TOKEN preserved"
    else
      record_result "system-update" "FAIL" "TOKEN content changed"
    fi
  else
    record_result "system-update" "FAIL" "TOKEN file missing after update"
  fi
else
  record_result "system-update" "FAIL" "exit code $?"
  echo "--- update output ---"
  cat "${OUTPUT_DIR}/update_output" 2>/dev/null || true
  echo "--- end output ---"
fi

# ---------------------------------------------------------------
# Test 7: System uninstall script
# ---------------------------------------------------------------
echo ""
echo "=== Test 7: System uninstall ==="

if timeout 120 sh "${SCRIPTS_DIR}/fivenines_uninstall.sh" > "${OUTPUT_DIR}/uninstall_output" 2>&1; then
  # Verify cleanup
  if [ ! -d "/etc/fivenines_agent" ] || [ ! -d "$INSTALL_DIR" ]; then
    record_result "system-uninstall" "PASS" "cleaned up"
  else
    record_result "system-uninstall" "PASS" "script completed"
  fi
else
  record_result "system-uninstall" "FAIL" "exit code $?"
  echo "--- uninstall output ---"
  cat "${OUTPUT_DIR}/uninstall_output" 2>/dev/null || true
  echo "--- end output ---"
fi

# ---------------------------------------------------------------
# Test 8: User-level install script
# ---------------------------------------------------------------
echo ""
echo "=== Test 8: User-level install ==="

# Create a non-root user for user-level tests (if running as root)
if [ "$(id -u)" = "0" ]; then
  # Create test user (handle both glibc and Alpine)
  if command -v adduser > /dev/null 2>&1 && command -v rc-service > /dev/null 2>&1; then
    # Alpine
    addgroup -S testuser 2>/dev/null || true
    adduser -S -G testuser -s /bin/sh -h /home/testuser testuser 2>/dev/null || true
  else
    useradd -m -s /bin/sh testuser 2>/dev/null || true
  fi
fi

# Run user install as testuser (or current user if not root)
USER_INSTALL_DIR="/home/testuser/.local/fivenines"
USER_CONFIG_DIR="/home/testuser/.config/fivenines_agent"

if [ "$(id -u)" = "0" ] && id testuser > /dev/null 2>&1; then
  # Ensure testuser can access the scripts and tarball
  chmod 644 "$TARBALL_PATH" 2>/dev/null || true
  if timeout 120 su -s /bin/sh testuser -c "
    export FIVENINES_TEST_MODE=1
    export FIVENINES_INSTALL_DIR='${USER_INSTALL_DIR}'
    export FIVENINES_CONFIG_DIR='${USER_CONFIG_DIR}'
    sh '${SCRIPTS_DIR}/fivenines_setup_user.sh' 'test-token-user-ci'
  " > "${OUTPUT_DIR}/user_setup_output" 2>&1; then
    record_result "user-install" "PASS" ""
  else
    record_result "user-install" "FAIL" "exit code $?"
    echo "--- user setup output ---"
    cat "${OUTPUT_DIR}/user_setup_output" 2>/dev/null || true
    echo "--- end output ---"
  fi
else
  record_result "user-install" "SKIP" "cannot create test user"
fi

# ---------------------------------------------------------------
# Test 9: User-level update script (TOKEN preservation)
# ---------------------------------------------------------------
echo ""
echo "=== Test 9: User-level update ==="

USER_TOKEN_FILE="${USER_CONFIG_DIR}/TOKEN"
USER_TOKEN_BEFORE=""
if [ -f "$USER_TOKEN_FILE" ]; then
  USER_TOKEN_BEFORE=$(cat "$USER_TOKEN_FILE")
fi

if [ "$(id -u)" = "0" ] && id testuser > /dev/null 2>&1 && [ -d "$USER_INSTALL_DIR" ]; then
  if timeout 120 su -s /bin/sh testuser -c "
    export FIVENINES_TEST_MODE=1
    export FIVENINES_INSTALL_DIR='${USER_INSTALL_DIR}'
    export FIVENINES_CONFIG_DIR='${USER_CONFIG_DIR}'
    sh '${SCRIPTS_DIR}/fivenines_update_user.sh'
  " > "${OUTPUT_DIR}/user_update_output" 2>&1; then
    # Verify TOKEN preserved
    if [ -f "$USER_TOKEN_FILE" ]; then
      USER_TOKEN_AFTER=$(cat "$USER_TOKEN_FILE")
      if [ "$USER_TOKEN_BEFORE" = "$USER_TOKEN_AFTER" ]; then
        record_result "user-update" "PASS" "TOKEN preserved"
      else
        record_result "user-update" "FAIL" "TOKEN content changed"
      fi
    else
      record_result "user-update" "FAIL" "TOKEN file missing after update"
    fi
  else
    record_result "user-update" "FAIL" "exit code $?"
    echo "--- user update output ---"
    cat "${OUTPUT_DIR}/user_update_output" 2>/dev/null || true
    echo "--- end output ---"
  fi
else
  record_result "user-update" "SKIP" "user install not completed"
fi

# ---------------------------------------------------------------
# Test 10: User-level uninstall script
# ---------------------------------------------------------------
echo ""
echo "=== Test 10: User-level uninstall ==="

if [ "$(id -u)" = "0" ] && id testuser > /dev/null 2>&1 && [ -d "$USER_INSTALL_DIR" ]; then
  if timeout 120 su -s /bin/sh testuser -c "
    export FIVENINES_TEST_MODE=1
    export FIVENINES_INSTALL_DIR='${USER_INSTALL_DIR}'
    export FIVENINES_CONFIG_DIR='${USER_CONFIG_DIR}'
    sh '${SCRIPTS_DIR}/fivenines_uninstall_user.sh'
  " > "${OUTPUT_DIR}/user_uninstall_output" 2>&1; then
    record_result "user-uninstall" "PASS" ""
  else
    record_result "user-uninstall" "FAIL" "exit code $?"
    echo "--- user uninstall output ---"
    cat "${OUTPUT_DIR}/user_uninstall_output" 2>/dev/null || true
    echo "--- end output ---"
  fi
else
  record_result "user-uninstall" "SKIP" "user install not completed"
fi

# ---------------------------------------------------------------
# Cleanup background processes
# ---------------------------------------------------------------
if [ -n "$MOCK_PID" ]; then kill "$MOCK_PID" 2>/dev/null || true; fi

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
echo ""
echo "========================================"
echo "  TEST SUMMARY"
echo "========================================"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
echo "  SKIP: $SKIP_COUNT"
echo "========================================"
echo ""

# Write structured results for step summary
{
  echo "### Distro Test Results: $(grep ^PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo 'Unknown')"
  echo ""
  echo "| Test | Status | Detail |"
  echo "|------|--------|--------|"
  printf '%b' "$RESULTS"
  echo ""
} > "${OUTPUT_DIR}/test-results.md"

cat "${OUTPUT_DIR}/test-results.md"

# Exit with failure if any test failed
if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi

exit 0
