# Synology DSM SPK Packaging

This directory contains scaffolding to build and package fivenines-agent for
Synology DSM 7 as an SPK (Synology Package).

## Prerequisites

- DSM 7.0 or later (tested on DSM 7.x)
- x86_64 or aarch64 architecture NAS
- A fivenines.io account with an API token

## Build

### 1. Build the binary

Run inside the manylinux2014 Docker build environment (same as CI):

```bash
TARGET_ARCH=amd64 ./py2exe_synology.sh
# or
TARGET_ARCH=arm64 ./py2exe_synology.sh
```

This produces `./dist/linux/fivenines-agent-synology-{amd64|arm64}/`.

Key differences from the standard build:
- libvirt-python is uninstalled (not available on NAS hardware)
- systemd-watchdog is uninstalled (DSM does not use systemd)
- libtirpc is not bundled (only needed for libvirt)

### 2. Assemble the SPK

```bash
./synology/build_spk.sh 1.5.4 x86_64
# or
./synology/build_spk.sh 1.5.4 aarch64
```

The SPK is written to `./dist/synology/fivenines-agent-<version>-<arch>.spk`.

## Installation

1. Open Synology Package Center
2. Click **Manual Install**
3. Upload the `.spk` file
4. Follow the wizard — enter your fivenines.io API token when prompted
5. The agent starts automatically after installation

The token is stored at `/var/packages/fivenines-agent/etc/TOKEN`.

## File Structure

```
synology/
  INFO.template            Package metadata (VERSION and ARCH are substituted)
  build_spk.sh             Assembles the SPK from a built binary
  scripts/
    start-stop-status      DSM service lifecycle script
    postinst               Writes wizard token to config file
  conf/
    privilege              DSM 7 privilege declaration (runs as root)
  WIZARD_UIFILES/
    install_uifile         Token input UI shown during Package Center install
```

## Notes

- The agent runs as `sc-fivenines-agent` (a custom low-privilege internal user).
  Because it does not run as `root`, some deep system telemetry (e.g., SMART data, hardware sensors) may be inaccessible depending on your NAS model's file permissions. This is gracefully handled and ignored.
- QEMU/libvirt and Proxmox monitoring are gracefully disabled (the libraries
  are not available on NAS hardware).
- synopkg is supported for package security scanning.
- Log file: `/var/packages/fivenines-agent/var/agent.log`
- PID file: `/var/packages/fivenines-agent/var/agent.pid`
