#!/usr/bin/env bash
# Domain-controller E2E for the Windows MSI, which no GitHub runner can run
# itself (promoting a runner to a DC needs a reboot): install a Windows Server
# evaluation ISO in QEMU/KVM, let stage1.ps1 promote it to the first DC of a
# new forest and stage2.ps1 play the account scenarios against the MSI. The VM
# reports on its serial port and powers itself off.
#
# Usage: run-vm.sh ISO LANG NEW_MSI OLD_MSI OUT_DIR
#   LANG     the Windows language tag, e.g. en-US or de-DE
#   OLD_MSI  the last release before domain-controller support (v1.22.0),
#            whose failure stage2 reproduces first
# Needs: KVM, qemu-system-x86, qemu-utils, genisoimage, wimtools, socat,
# ntfs-3g, and sudo (to read the ISO's image list and the VM's disk).
set -euo pipefail

iso=$1
lang=$2
new_msi=$3
old_msi=$4
out=$5

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=$(mktemp -d)
mkdir -p "$out/screens"

# The Standard Core image, whatever its index on this ISO.
sudo mkdir -p "$work/iso"
sudo mount -o loop,ro "$iso" "$work/iso"
wiminfo "$work/iso/sources/install.wim" > "$out/wiminfo.txt"
sudo umount "$work/iso"
index=$(awk '/^Index:/ { i = $2 } /^Name:/ && $NF == "SERVERSTANDARDCORE" { print i; exit }' "$out/wiminfo.txt")
if [ -z "$index" ]; then
    echo "no SERVERSTANDARDCORE image in $iso" >&2
    cat "$out/wiminfo.txt" >&2
    exit 1
fi
echo "Installing image $index (Standard Core), language $lang"

# A throwaway Administrator / DSRM password for a VM nothing can reach
# (user-mode networking, no port forwarded). Hex only: no XML escaping.
password="Fn9-$(openssl rand -hex 12)-Aa"

payload="$work/payload"
mkdir -p "$payload/fivenines-dc"
sed -e "s/@LANG@/$lang/g" \
    -e "s/@IMAGE_INDEX@/$index/g" \
    -e "s/@ADMIN_PASSWORD@/$password/g" \
    -e "s/@COMPUTER_NAME@/KAGSRV/g" \
    "$here/autounattend.xml.in" > "$payload/autounattend.xml"
cp "$here/common.ps1" "$here/stage1.ps1" "$here/stage2.ps1" "$payload/fivenines-dc/"
cp "$repo/fivenines_setup.ps1" "$repo/fivenines_update.ps1" "$repo/fivenines_uninstall.ps1" "$payload/fivenines-dc/"
cp "$new_msi" "$payload/fivenines-dc/new.msi"
cp "$old_msi" "$payload/fivenines-dc/old.msi"
printf '%s' "$password" > "$payload/fivenines-dc/password.txt"
genisoimage -quiet -J -R -input-charset utf-8 -V FNPAYLOAD -o "$work/payload.iso" "$payload"

qemu-img create -q -f qcow2 "$work/disk.qcow2" 40G

# cache=unsafe: QEMU ignores the guest's flushes on the system disk. Windows
# servicing flushes after nearly every write, and with the default cache each
# flush waits for an fsync of the runner's disk: on a runner whose disk was
# slow to sync, Install-WindowsFeature AD-Domain-Services took 6 minutes to
# commit its files instead of 4 seconds, DFSR then did not start within the
# service timeout, the servicing stack failed and the role install gave up
# after an hour ("could not update the provided feature files in the time
# allowed"). Losing the guest's writes on a host crash costs nothing here: the
# disk is thrown away, and QEMU writes everything out when it exits (SIGTERM
# included), before the logs are read from it below.
serial="$out/serial.log"
: > "$serial"
qemu-system-x86_64 \
    -machine q35,accel=kvm -cpu host -smp 4 -m 8192 \
    -rtc base=localtime \
    -device ahci,id=ahci \
    -drive file="$work/disk.qcow2",if=none,id=disk,format=qcow2,cache=unsafe \
    -device ide-hd,drive=disk,bus=ahci.0,bootindex=0 \
    -drive file="$iso",if=none,id=install,media=cdrom,readonly=on \
    -device ide-cd,drive=install,bus=ahci.1,bootindex=1 \
    -drive file="$work/payload.iso",if=none,id=payload,media=cdrom,readonly=on \
    -device ide-cd,drive=payload,bus=ahci.2 \
    -netdev user,id=net0 -device e1000e,netdev=net0 \
    -vga std -display none \
    -serial file:"$serial" \
    -monitor unix:"$work/monitor.sock",server,nowait &
qemu=$!

# Follow the serial log until the VM powers off (tail exits with QEMU); a
# screenshot every 3 minutes shows where Setup or a stage stopped when
# nothing reaches the serial port.
tail -n +1 -f --pid="$qemu" "$serial" &
follower=$!
deadline=$(( $(date +%s) + ${FN_VM_TIMEOUT_MIN:-130} * 60 ))
shot=0
timed_out=0
while kill -0 "$qemu" 2>/dev/null; do
    sleep 30
    if [ $(( $(date +%s) / 180 )) -ne "$shot" ]; then
        shot=$(( $(date +%s) / 180 ))
        ( echo "screendump $out/screens/$(date +%H%M%S).png -f png" | socat - UNIX-CONNECT:"$work/monitor.sock" ) > /dev/null 2>&1 || true
    fi
    if [ "$(date +%s)" -gt "$deadline" ]; then
        echo "timed out waiting for the VM; killing it" >&2
        ( echo "screendump $out/screens/timeout.png -f png" | socat - UNIX-CONNECT:"$work/monitor.sock" ) > /dev/null 2>&1 || true
        sleep 2
        kill "$qemu" 2>/dev/null || true
        timed_out=1
        break
    fi
done
wait "$qemu" 2>/dev/null || true
wait "$follower" 2>/dev/null || true

# The VM's own logs (MSI, setup, progress), read from its disk. Best effort:
# a VM killed mid-write may leave an NTFS volume ntfs-3g will not mount. The
# steps are chained with &&: errexit is off on the left of ||, so a failed
# mount would otherwise carry on silently.
sudo modprobe nbd max_part=8 &&
    sudo qemu-nbd --connect=/dev/nbd0 --read-only "$work/disk.qcow2" &&
    sleep 2 &&
    sudo mkdir -p "$work/c" &&
    sudo mount -t ntfs-3g -o ro /dev/nbd0p1 "$work/c" &&
    mkdir -p "$out/vm" &&
    { sudo cp -r "$work/c/fn/logs" "$work/c/fn/progress.log" "$out/vm/" 2>/dev/null || true; } &&
    { sudo cp -r "$work/c/ProgramData/fivenines_agent/logs" "$out/vm/agent-logs" 2>/dev/null || true; } &&
    { sudo cp "$work/c/Windows/Panther/setupact.log" "$work/c/Windows/Panther/setuperr.log" "$out/vm/" 2>/dev/null || true; } &&
    sudo umount "$work/c" &&
    sudo chown -R "$(id -u):$(id -g)" "$out/vm" ||
    echo "could not read the VM's disk" >&2
sudo qemu-nbd --disconnect /dev/nbd0 > /dev/null 2>&1 || true

if [ "$timed_out" -eq 0 ] && grep -q "FN-RESULT: PASS" "$serial"; then
    echo "Domain-controller E2E passed."
    exit 0
fi
echo "Domain-controller E2E failed (see the serial log above and the artifacts)." >&2
exit 1
