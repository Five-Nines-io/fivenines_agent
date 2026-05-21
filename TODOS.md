# TODOS

## P3: Docker image caching for CI resilience

Mirror the 14 distro base images used in `test-distro-matrix` to ghcr.io or use
a Docker pull-through cache. Currently, all distro tests pull from Docker Hub
directly. A Docker Hub outage or rate-limit event would block the entire CI
pipeline.

- **Effort:** M (human) / S (CC)
- **Depends on:** #30 (distro regression testing) shipping first
- **Files:** `.github/workflows/build-release.yml`

## P3: Nightly distro matrix runs

Add a `schedule` trigger to the distro regression testing workflow to run the
matrix nightly or weekly. This catches upstream distro changes (new Alpine
minor release changing BusyBox behavior, new Ubuntu release changing adduser
flags) before users do.

- **Effort:** S (human) / S (CC)
- **Depends on:** #30 (distro regression testing) shipping first
- **Files:** `.github/workflows/build-release.yml` (add `schedule:` trigger)

## P2: Promote Rocky 10 to blocking

The `rockylinux:10` test matrix entry runs with `allow_failure: "1"` because the
Docker image does not exist yet. When Rocky Linux 10 GA ships and the Docker image
is available on Docker Hub, remove `allow_failure` from the matrix entry so that
RHEL 10 generation regressions block releases.

- **Effort:** S (human) / S (CC)
- **Depends on:** Rocky Linux 10 GA release
- **Files:** `.github/workflows/build-release.yml` (remove `allow_failure: "1"` from rockylinux:10 entry)

## P2: Windows-native service collectors (Phase 2)

After Windows Server support ships, add native Windows collectors that parallel
the existing Linux service integrations: Event Log (security signal, parallels
fail2ban), IIS (parallels nginx/caddy), MSSQL (parallels postgresql), Hyper-V
(parallels qemu/proxmox), and Microsoft Defender status. Each plugs into the
collector registry with its own Windows capability probe. Customer-pull-driven.

- **Effort:** L (human) / M (CC)
- **Depends on:** Windows Server support shipping first (see `docs/windows-server-support-plan.md`)
- **Files:** new collector modules, `collectors.py`, `permissions.py`

## P2: Ship Windows OS hotfixes to the security scanner

The Windows registry-based package collector (`packages.py::_get_packages_windows_registry`)
captures user-installed software but NOT Windows OS updates (KB articles), which
are installed via the Servicing Stack and live in a separate store. That's a
blind spot for the security scanner - half of Windows-relevant CVEs are in the
OS itself.

Collect hotfixes via WMI `Win32_QuickFixEngineering` (or the `Get-HotFix`
PowerShell wrapper) and either include them in the `packages` payload with a
recognizable prefix (e.g. `KB5043076`) or ship them under a separate
`windows_hotfixes` payload key. Add a backend handoff doc entry once the
shape is decided.

- **Effort:** S (human) / S (CC)
- **Depends on:** Windows Server support shipping first
- **Files:** `fivenines_agent/packages.py` (or a new `windows_hotfixes.py`),
  `permissions.py` (capability probe), `docs/windows-backend-handoff.md` (#14
  update), backend CPE matcher
- **See:** entry #14 in `docs/windows-backend-handoff.md`
