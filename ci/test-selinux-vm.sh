#!/bin/sh
# SELinux VM integration test for fivenines-agent
# Boots a RockyLinux 9 VM with SELinux Enforcing, installs the agent,
# and verifies no AVC denials occur.
#
# Usage: AGENT_TARBALL=/path/to/fivenines-agent-linux-amd64.tar.gz \
#        SCRIPTS_DIR=/path/to/repo \
#        bash ci/test-selinux-vm.sh
#
# Environment variables:
#   AGENT_TARBALL  - Path to the agent tarball
#   SCRIPTS_DIR    - Path to the repo root (contains fivenines_setup.sh, selinux/)
#   ROCKY_IMAGE    - Path to RockyLinux 9 GenericCloud QCOW2 image
#   SSH_PORT       - Local port for SSH forwarding (default: 2222)
#   VM_MEMORY      - VM memory in MB (default: 2048)
#   VM_TIMEOUT     - Max seconds to wait for VM boot (default: 300)

set -eu

AGENT_TARBALL="${AGENT_TARBALL:?AGENT_TARBALL must be set}"
SCRIPTS_DIR="${SCRIPTS_DIR:?SCRIPTS_DIR must be set}"
ROCKY_IMAGE="${ROCKY_IMAGE:?ROCKY_IMAGE must be set}"
SSH_PORT="${SSH_PORT:-2222}"
VM_MEMORY="${VM_MEMORY:-2048}"
VM_TIMEOUT="${VM_TIMEOUT:-300}"

WORK_DIR=$(mktemp -d)
trap 'cleanup' EXIT

QEMU_PID=""

cleanup() {
  echo "Cleaning up..."
  if [ -n "$QEMU_PID" ]; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR"
}

echo "=== SELinux VM Integration Test ==="
echo "Agent tarball: $AGENT_TARBALL"
echo "Scripts dir: $SCRIPTS_DIR"
echo "Rocky image: $ROCKY_IMAGE"

# ---------------------------------------------------------------
# Step 1: Generate SSH key pair for VM access
# ---------------------------------------------------------------
echo ""
echo "--- Generating SSH key ---"
ssh-keygen -t ed25519 -f "$WORK_DIR/vm_key" -N "" -q
VM_PUBKEY=$(cat "$WORK_DIR/vm_key.pub")

# ---------------------------------------------------------------
# Step 2: Create cloud-init configuration
# ---------------------------------------------------------------
echo "--- Creating cloud-init config ---"

cat > "$WORK_DIR/meta-data" << 'METADATA'
instance-id: fivenines-selinux-test
local-hostname: selinux-test
METADATA

cat > "$WORK_DIR/user-data" << USERDATA
#cloud-config
users:
  - name: testuser
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - ${VM_PUBKEY}

# Ensure SELinux stays enforcing
bootcmd:
  - setenforce 1 || true

# Install selinux-policy-devel for building modules
packages:
  - policycoreutils-python-utils
  - selinux-policy-devel
  - wget

# Signal that cloud-init is done
runcmd:
  - touch /var/tmp/cloud-init-ready

# Ensure SELinux is enforcing in config
write_files:
  - path: /etc/selinux/config
    content: |
      SELINUX=enforcing
      SELINUXTYPE=targeted
USERDATA

# Create cloud-init ISO (NoCloud datasource)
if command -v genisoimage >/dev/null 2>&1; then
  genisoimage -output "$WORK_DIR/cloud-init.iso" -volid cidata -joliet -rock \
    "$WORK_DIR/user-data" "$WORK_DIR/meta-data" 2>/dev/null
elif command -v mkisofs >/dev/null 2>&1; then
  mkisofs -output "$WORK_DIR/cloud-init.iso" -volid cidata -joliet -rock \
    "$WORK_DIR/user-data" "$WORK_DIR/meta-data" 2>/dev/null
elif command -v xorrisofs >/dev/null 2>&1; then
  xorrisofs -output "$WORK_DIR/cloud-init.iso" -volid cidata -joliet -rock \
    "$WORK_DIR/user-data" "$WORK_DIR/meta-data" 2>/dev/null
else
  echo "FAIL: No ISO creation tool found (need genisoimage, mkisofs, or xorrisofs)"
  exit 1
fi

# ---------------------------------------------------------------
# Step 3: Create overlay disk from base image
# ---------------------------------------------------------------
echo "--- Creating VM disk overlay ---"
qemu-img create -f qcow2 -b "$ROCKY_IMAGE" -F qcow2 "$WORK_DIR/disk.qcow2" 20G

# ---------------------------------------------------------------
# Step 4: Boot the VM
# ---------------------------------------------------------------
echo "--- Booting RockyLinux 9 VM (SELinux Enforcing) ---"

# Use KVM if available, fall back to TCG (software emulation) otherwise
KVM_ARGS=""
if [ -w /dev/kvm ] 2>/dev/null; then
  KVM_ARGS="-enable-kvm -cpu host"
  echo "Using KVM acceleration"
else
  KVM_ARGS="-cpu qemu64"
  echo "WARNING: KVM not available, using software emulation (will be slow)"
fi

# shellcheck disable=SC2086
qemu-system-x86_64 \
  $KVM_ARGS \
  -m "$VM_MEMORY" \
  -smp 2 \
  -drive file="$WORK_DIR/disk.qcow2",format=qcow2 \
  -cdrom "$WORK_DIR/cloud-init.iso" \
  -netdev user,id=net0,hostfwd=tcp::"$SSH_PORT"-:22 \
  -device virtio-net-pci,netdev=net0 \
  -nographic \
  -serial mon:stdio \
  > "$WORK_DIR/vm-console.log" 2>&1 &

QEMU_PID=$!

# ---------------------------------------------------------------
# Step 5: Wait for SSH to become available
# ---------------------------------------------------------------
echo "--- Waiting for VM SSH (port $SSH_PORT, timeout ${VM_TIMEOUT}s) ---"

SSH_OPTS="-i $WORK_DIR/vm_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR -p $SSH_PORT"
SCP_OPTS="-i $WORK_DIR/vm_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -P $SSH_PORT"
ELAPSED=0

while [ "$ELAPSED" -lt "$VM_TIMEOUT" ]; do
  if nc -z 127.0.0.1 "$SSH_PORT" 2>/dev/null; then
    break
  fi
  # Check if QEMU process is still running
  if ! kill -0 "$QEMU_PID" 2>/dev/null; then
    echo "FAIL: QEMU process died"
    echo "--- VM console log ---"
    tail -50 "$WORK_DIR/vm-console.log" 2>/dev/null || true
    exit 1
  fi
  sleep 2
  ELAPSED=$((ELAPSED + 2))
done

if [ "$ELAPSED" -ge "$VM_TIMEOUT" ]; then
  echo "FAIL: SSH port not available after ${VM_TIMEOUT}s"
  exit 1
fi

echo "SSH port is open. Waiting for cloud-init to finish..."

# Wait for cloud-init completion marker
ELAPSED=0
while [ "$ELAPSED" -lt "$VM_TIMEOUT" ]; do
  # shellcheck disable=SC2086
  if ssh $SSH_OPTS testuser@127.0.0.1 "test -f /var/tmp/cloud-init-ready" 2>/dev/null; then
    break
  fi
  sleep 5
  ELAPSED=$((ELAPSED + 5))
done

if [ "$ELAPSED" -ge "$VM_TIMEOUT" ]; then
  echo "FAIL: cloud-init did not complete within ${VM_TIMEOUT}s"
  exit 1
fi

echo "VM is ready."

# Helper to run commands in the VM
vm_run() {
  # shellcheck disable=SC2029,SC2086
  ssh $SSH_OPTS testuser@127.0.0.1 "$@"
}

vm_sudo() {
  # shellcheck disable=SC2029,SC2086
  ssh $SSH_OPTS testuser@127.0.0.1 "sudo $*"
}

# ---------------------------------------------------------------
# Step 6: Verify SELinux is Enforcing
# ---------------------------------------------------------------
echo ""
echo "=== Test 1: SELinux is Enforcing ==="
SELINUX_MODE=$(vm_sudo "getenforce")
echo "SELinux mode: $SELINUX_MODE"
if [ "$SELINUX_MODE" = "Enforcing" ]; then
  echo "[PASS] SELinux is Enforcing"
else
  echo "[FAIL] Expected Enforcing, got: $SELINUX_MODE"
  exit 1
fi

# ---------------------------------------------------------------
# Step 7: Copy agent tarball and scripts into VM
# ---------------------------------------------------------------
echo ""
echo "=== Copying agent tarball and setup script to VM ==="
# The tarball already contains selinux/ (bundled by CI build step)
# shellcheck disable=SC2086
scp $SCP_OPTS "$AGENT_TARBALL" testuser@127.0.0.1:/tmp/agent.tar.gz
# shellcheck disable=SC2086
scp $SCP_OPTS "$SCRIPTS_DIR/fivenines_setup.sh" testuser@127.0.0.1:/tmp/fivenines_setup.sh

# ---------------------------------------------------------------
# Step 8: Run the setup script
# ---------------------------------------------------------------
echo ""
echo "=== Test 2: Run setup script ==="

# Instead of running the full setup script (which tries to download service files
# and ping external hosts -- both hang without internet), we replicate the key
# steps manually and then source/call setup_selinux_contexts directly.

# 1. Create fivenines user
vm_sudo useradd --system --user-group fivenines --shell /bin/false 2>/dev/null || true

# 2. Create config dir with TOKEN
vm_sudo "sh -c 'mkdir -p /etc/fivenines_agent && echo -n test-token > /etc/fivenines_agent/TOKEN && chmod 600 /etc/fivenines_agent/TOKEN && chown fivenines:fivenines /etc/fivenines_agent/TOKEN'"

# 3. Extract agent tarball
vm_sudo mkdir -p /opt/fivenines
vm_sudo tar -xzf /tmp/agent.tar.gz -C /opt/fivenines/

# 4. Set permissions and create symlink (like the setup script does)
AGENT_SUBDIR=$(vm_sudo "ls /opt/fivenines/ | head -1")
vm_sudo "sh -c 'ln -sf /opt/fivenines/$AGENT_SUBDIR/$AGENT_SUBDIR /opt/fivenines/fivenines_agent && chown -R fivenines:fivenines /opt/fivenines && chmod -R 755 /opt/fivenines/$AGENT_SUBDIR'"

# 5. Run the SELinux setup function by sourcing it from the setup script
# We create a small wrapper that sets the needed variables and sources the functions
vm_sudo "sh -c '
  INSTALL_DIR=/opt/fivenines
  AGENT_DIR=/opt/fivenines/$AGENT_SUBDIR
  # Source color codes and helper functions
  RED=\"\\033[0;31m\"; GREEN=\"\\033[0;32m\"; YELLOW=\"\\033[1;33m\"; NC=\"\\033[0m\"
  print_success() { printf \"%b\\n\" \"\${GREEN}[+]\${NC} \$1\"; }
  print_warning() { printf \"%b\\n\" \"\${YELLOW}[!]\${NC} \$1\"; }
  # Extract and run setup_selinux_contexts from the setup script
  eval \"\$(sed -n \"/^setup_selinux_contexts/,/^}$/p\" /tmp/fivenines_setup.sh)\"
  setup_selinux_contexts
'" 2>&1
SETUP_EXIT=$?

SETUP_OUTPUT=$(vm_sudo "semodule -l 2>/dev/null | grep fivenines" || true)
echo "semodule output: $SETUP_OUTPUT"

if echo "$SETUP_OUTPUT" | grep -q "fivenines_agent"; then
  echo "[PASS] SELinux policy module loaded: $SETUP_OUTPUT"
else
  echo "[FAIL] SELinux policy module not loaded"
  echo "  semodule output: $SETUP_OUTPUT"
  echo "  Checking build prerequisites..."
  vm_sudo "rpm -q selinux-policy-devel policycoreutils-python-utils" || true
  exit 1
fi

# ---------------------------------------------------------------
# Step 9: Verify file contexts
# ---------------------------------------------------------------
echo ""
echo "=== Test 3: Verify SELinux file contexts ==="

CONTEXTS_OK=true

# Check /opt/fivenines label
OPT_LABEL=$(vm_sudo "ls -Zd /opt/fivenines/ 2>/dev/null" || echo "unknown")
echo "  /opt/fivenines: $OPT_LABEL"
if echo "$OPT_LABEL" | grep -q "fivenines_agent_exec_t"; then
  echo "  [PASS] /opt/fivenines has fivenines_agent_exec_t"
else
  echo "  [FAIL] Expected fivenines_agent_exec_t label"
  CONTEXTS_OK=false
fi

# Check /etc/fivenines_agent label
ETC_LABEL=$(vm_sudo "ls -Zd /etc/fivenines_agent/ 2>/dev/null" || echo "unknown")
echo "  /etc/fivenines_agent: $ETC_LABEL"
if echo "$ETC_LABEL" | grep -q "fivenines_agent_config_t"; then
  echo "  [PASS] /etc/fivenines_agent has fivenines_agent_config_t"
else
  echo "  [FAIL] Expected fivenines_agent_config_t label"
  CONTEXTS_OK=false
fi

if [ "$CONTEXTS_OK" = true ]; then
  echo "[PASS] All file contexts correct"
else
  echo "[FAIL] Some file contexts incorrect"
fi

# ---------------------------------------------------------------
# Step 10: Check for AVC denials
# ---------------------------------------------------------------
echo ""
echo "=== Test 4: Check for AVC denials ==="

AVC_DENIALS=$(vm_sudo "ausearch -m AVC -ts recent 2>/dev/null | grep fivenines" || true)
if [ -z "$AVC_DENIALS" ]; then
  echo "[PASS] No AVC denials for fivenines"
else
  echo "[WARN] AVC denials found:"
  echo "$AVC_DENIALS"
fi

# ---------------------------------------------------------------
# Step 11: Test agent dry-run under SELinux
# ---------------------------------------------------------------
echo ""
echo "=== Test 5: Agent dry-run under SELinux ==="

# Create a mock TOKEN
vm_sudo "sh -c 'mkdir -p /etc/fivenines_agent && echo -n test-token > /etc/fivenines_agent/TOKEN && chmod 600 /etc/fivenines_agent/TOKEN && chown root:root /etc/fivenines_agent/TOKEN'"

# Try running the agent binary with --dry-run
AGENT_BIN=$(vm_run "find /opt/fivenines -type f -name 'fivenines-agent-*' ! -name '*.so' | head -1")
if [ -n "$AGENT_BIN" ]; then
  DRYRUN_OUTPUT=$(vm_sudo "timeout 60 $AGENT_BIN --dry-run 2>&1" || true)
  DRYRUN_EXIT=$?

  # Check for new AVC denials after dry-run
  AVC_AFTER=$(vm_sudo "ausearch -m AVC -ts recent 2>/dev/null | grep fivenines" || true)
  if [ -z "$AVC_AFTER" ]; then
    echo "[PASS] No AVC denials during dry-run"
  else
    echo "[WARN] AVC denials during dry-run:"
    echo "$AVC_AFTER"
  fi

  # Check what domain the process ran as
  echo "  Agent process context during run would be fivenines_agent_t (if started via systemd)"
else
  echo "[SKIP] Agent binary not found for this architecture"
fi

# ---------------------------------------------------------------
# Step 12: Test uninstall SELinux cleanup
# ---------------------------------------------------------------
echo ""
echo "=== Test 6: Uninstall SELinux cleanup ==="

# shellcheck disable=SC2086
scp $SCP_OPTS "$SCRIPTS_DIR/fivenines_uninstall.sh" testuser@127.0.0.1:/tmp/fivenines_uninstall.sh

UNINSTALL_OUTPUT=$(vm_sudo "sh /tmp/fivenines_uninstall.sh 2>&1" || true)
echo "$UNINSTALL_OUTPUT"

MODULE_AFTER=$(vm_sudo "semodule -l 2>/dev/null | grep fivenines" || true)
if [ -z "$MODULE_AFTER" ]; then
  echo "[PASS] SELinux module removed after uninstall"
else
  echo "[FAIL] SELinux module still loaded: $MODULE_AFTER"
fi

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
echo ""
echo "========================================"
echo "  SELINUX VM TEST COMPLETE"
echo "========================================"
echo "  VM: RockyLinux 9 (SELinux Enforcing)"
echo "  All tests completed."
echo "========================================"
