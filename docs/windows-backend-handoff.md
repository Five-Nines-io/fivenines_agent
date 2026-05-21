# Windows agent: backend handoff notes

Running log of decisions made during the Windows port that affect the
backend (fivenines.io API + dashboard). Each entry is self-contained so
whoever updates the backend can work through them one at a time.

The Windows agent is functionally complete and shipping metrics to the
existing `/collect` endpoint. The backend already accepts the payloads
(they're just JSON), so nothing is *broken* — but the dashboard will show
gaps, misleading values, or N/A columns until these are wired through.

Format of each entry:
- **Decision** — what was decided and why
- **Agent change** — file + summary of what the agent now does
- **Backend TODO** — what needs to happen on the dashboard / API side

---

## 1. `load_average` is omitted on Windows payloads

- **Decision (2026-05-21).** Drop `load_average` entirely from Windows
  payloads. Windows has no native equivalent (no kernel load-avg, no
  D-state). `psutil.getloadavg()` emulates by spawning a background thread
  that samples CPU activity every 5s, but:
  - A freshly-started process always reports `(0.0, 0.0, 0.0)`.
  - Idle systems report zero indefinitely (CPU-only sampling, no I/O wait).
  - Service restarts reset the counter.
  - The number is *not* directly comparable to the Linux value of the same name.
  Shipping a fake value would be more misleading than informative.
- **Agent change.** `fivenines_agent/agent.py::_collect_metrics` skips the
  `data["load_average"] = ...` line when `is_windows()`. `permissions.py`
  also omits `load_average` from `_build_windows_capabilities` and from
  `WINDOWS_BANNER_GROUPS`. Linux/macOS behavior unchanged.
- **Backend TODO.**
  - Don't expect `load_average` in the JSON payload from Windows hosts.
  - On the host detail page, hide the load-average chart for Windows hosts
    (OR show a small explanatory "not applicable on Windows" note — pick
    one style and apply consistently).
  - `capabilities.load_average` will be `undefined` on Windows hosts (the
    key is not in the dict, distinct from `false`). Anywhere the backend
    drives UI from `capabilities`, that's the signal.
  - On Linux hosts, behavior is unchanged — keep showing the chart.

---

## 2. File-handle metric: separate keys per OS (D2 / D10)

- **Decision.** Linux reports `file_handles_used` + `file_handles_limit`
  (a used/limit pair derived from `/proc/sys/fs/file-nr`). Windows reports
  `handle_count` (the total kernel handle count from the PDH counter
  `\Process(_Total)\Handle Count`). The two are semantically distinct —
  Linux file descriptors vs Windows kernel handles — so they ship under
  different keys instead of pretending they're the same metric.
- **Agent change.** `agent.py::_collect_file_handles` branches on
  `is_windows()`. `files.py` gained `handle_count()` for the Windows
  branch. Capability key `file_handles` is True on both OSes.
- **Backend TODO.**
  - Expect `handle_count` (integer) on Windows payloads, `file_handles_used`
    + `file_handles_limit` (integers) on Linux payloads. They will never
    appear together.
  - On the host detail page, show whichever one applies. Naming
    suggestion: "Open file handles" for Linux (with the used/limit ratio),
    "Open kernel handles" for Windows (just a count, no limit since
    Windows handles are bounded by available kernel memory, not a fixed
    file-table size).
  - On dashboard aggregates / fleet views, treat them as separate metrics;
    don't try to sum or average across OSes.

---

## 3. Windows-tailored capability set (D13)

- **Decision.** The Windows agent ships a Windows-shaped `capabilities`
  dict, not the Linux dict with Linux-only keys marked `false`. Linux-only
  capabilities are *absent* from the dict on Windows. Windows-native
  capabilities are *present* (and `false` if the relevant permission
  isn't granted, e.g. WMI Storage namespace access).
- **Agent change.** `permissions.py::_build_windows_capabilities` returns
  a different shape than `_build_linux_capabilities`.
- **Backend TODO.** When rendering the capabilities banner / host
  inspector, key off `capabilities.<key>` being `undefined` vs `true` vs
  `false`:
  - `undefined` → metric is not applicable on this OS, hide it
  - `false` → metric is applicable but the agent lacks permission, show
    "needs permission" hint
  - `true` → metric is being collected normally

  Reference list of Windows-specific keys:

  **Present on Windows (not on Linux):**
  - `disk_health` — boolean. True when the service account can query the
    `root\Microsoft\Windows\Storage` WMI namespace (the MSI grants this
    via a custom action). Drives the `disk_health` payload section
    (PhysicalDisk + StorageReliabilityCounter).
  - `software_inventory` — boolean. True when `HKLM\...\Uninstall` is
    readable. Drives the Windows half of the `/packages` sync flow.

  **Absent on Windows (Linux-only):**
  - `load_average` (see #1)
  - `raid_storage` / `zfs` / `fail2ban` / `proxmox` / `qemu` — these
    don't exist on Windows; the relevant collectors are not in the
    Windows binary at all
  - `smart_storage` — Linux uses `sudo smartctl`, Windows uses the WMI
    `disk_health` collector instead (see above)
  - `packages` — Linux dpkg/rpm/apk/pacman; Windows uses
    `software_inventory` instead

---

## 4. New payload section: `disk_health` (Windows only)

- **Decision.** Windows agent reports disk health via a new payload
  section called `disk_health`, populated by querying
  `MSFT_PhysicalDisk` + `MSFT_StorageReliabilityCounter` in the
  `root\Microsoft\Windows\Storage` WMI namespace. Subprocess-isolated
  with a 5-second timeout to prevent WMI hangs from blocking collection.
- **Agent change.** `fivenines_agent/disk_health_windows.py`. Registered
  in `collectors.py::COLLECTORS` under the `disk_health` config key.
- **Backend TODO.**
  - Accept a `disk_health` array in Windows payloads. Each entry contains
    fields like `friendly_name`, `health_status`, `operational_status`,
    `media_type`, `bus_type`, `serial_number`, `size_bytes`, plus
    reliability counters (`temperature`, `power_on_hours`,
    `read_errors_total`, `write_errors_total`, `wear`).
  - Display on a Windows-host detail page in place of where SMART data
    would appear for Linux hosts. The fields don't 1:1 map to SMART
    attributes — `wear` (percentage) is closest to SMART
    "Wear Leveling Count", `temperature` is a direct number, but
    SMART-specific attributes like raw read error rate don't exist.

---

## 5. Software inventory: registry-based on Windows

- **Decision.** Windows uses the registry's `Uninstall` keys
  (`HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall` and the
  `WOW6432Node` variant) as the source of installed software, instead of
  dpkg/rpm/apk/pacman.
- **Agent change.** `packages.py::_get_packages_windows_registry()`,
  dispatched from `get_installed_packages()` when `is_windows()`.
  `get_distro()` returns `"windows:<release>"` on Windows
  (e.g. `"windows:Windows Server 2025"`).
- **Backend TODO.**
  - Accept `distro` strings of the form `"windows:<release>"`. The release
    string comes from `platform.win32_ver()` and isn't sanitized further,
    so handle both common names ("Windows Server 2025", "11") and unusual
    SKU strings.
  - Package list shape is the same as Linux (`name`, `version`,
    `architecture` where available), so the existing `/packages` endpoint
    accepts the data as-is. The dashboard should be aware that Windows
    package names look like display names (`"Microsoft Edge"`) rather than
    package-manager names (`"microsoft-edge-stable"`).

---

## 6. `os_family` field in user context

- **Decision.** The `user_context` payload includes an `os_family` field
  on Windows (`"windows"`). The Linux/macOS user context doesn't include
  this key — it would always be redundant with what's already inferable
  from `uname.system`.
- **Agent change.** `env.py::_windows_user_context()` adds `"os_family":
  "windows"`.
- **Backend TODO.** Trivial — just don't choke on the extra key.

---

## 7. Service identity model

- **Decision.** Windows service runs as a dedicated local account
  `fivenines-agent` (machine-local, low-privilege), provisioned by the
  MSI. The account is in `Performance Monitor Users` (for PDH counters)
  and `Users` (for default Program Files read). Not LocalSystem.
- **Agent change.** The agent doesn't behave differently for this — the
  decision is enforced by `windows/installer/CreateServiceAccount.ps1`
  during install.
- **Backend TODO.**
  - The `user_context.username` on Windows payloads will be
    `fivenines-agent` (not the operator's name). For the dashboard's
    "running as" indicator, this is the expected value and shouldn't be
    flagged as suspicious.
  - `is_admin` / `is_root` will be `false` for normal Windows installs
    (the dedicated service account is not in the Administrators group).
    Don't show a "running as admin" warning — that's the correct config.

---

## 12. CPU times fields are platform-specific (Linux has `iowait`/`steal`/etc., Windows has `interrupt`/`dpc`)

- **Decision (2026-05-21).** No agent change. The `cpu` collector ships
  whatever fields `psutil.cpu_times_percent()` and `psutil.cpu_times()`
  return for the current platform. The set of fields differs per OS,
  which the backend needs to be aware of when reading the payload.
- **Context.** The `cpu` collector emits two per-core arrays:
  - `cpu_times_percent` (per-core, expressed as **% of that core's
    time**, sums to ~100 per core). Used for charts of "where is the
    CPU spending time" - user vs system vs idle vs platform-specific
    buckets.
  - `cpu_times` (per-core, expressed as **seconds since boot**). The
    cumulative counter; useful if the backend wants to compute its own
    deltas at a different time granularity than the agent's interval.

  Both come from psutil and inherit psutil's named-tuple shape, which
  varies by platform.
- **Field availability (from psutil docs):**

  | Field | Linux | macOS | Windows | Meaning |
  |---|---|---|---|---|
  | `user` | yes | yes | yes | normal processes in user mode (Linux also includes guest time here) |
  | `system` | yes | yes | yes | processes executing in kernel mode |
  | `idle` | yes | yes | yes | doing nothing |
  | `nice` | yes | yes | - | niced processes in user mode (Linux also includes guest_nice here) |
  | `iowait` | yes | - | - | waiting for I/O (NOT counted in idle on Linux) |
  | `irq` | yes (& BSD) | - | - | servicing hardware interrupts |
  | `softirq` | yes | - | - | servicing software interrupts |
  | `steal` | yes (>=2.6.11) | - | - | other OSes running in a virtualized env (KVM/Xen guest indicator) |
  | `guest` | yes (>=2.6.24) | - | - | running a virtual CPU for guest OSes |
  | `guest_nice` | yes (>=3.2.0) | - | - | running a niced virtual CPU for guest OSes |
  | `interrupt` | - | - | yes | servicing hardware interrupts (Windows-side equivalent of `irq`) |
  | `dpc` | - | - | yes | servicing Deferred Procedure Calls (interrupts at a lower priority than standard interrupts) |

- **Backend TODO.**
  - Accept the union of all possible field names in the per-core payload
    dicts. Missing fields = field doesn't apply to this OS.
  - For the per-core "CPU breakdown" chart:
    - Cross-platform bars: `user`, `system`, `idle`.
    - On Linux, additionally show `iowait`, `irq`, `softirq`, `steal`,
      `guest`. `steal` is particularly valuable on cloud VMs - it's
      the "noisy neighbor" indicator.
    - On Windows, additionally show `interrupt` and `dpc`. High `dpc`
      is the Windows-side equivalent signal of high `softirq` on
      Linux - usually a driver problem (often network or storage).
    - On macOS, only `user`/`system`/`idle`/`nice` are populated.
  - Field semantics differ subtly between OSes (Linux folds guest time
    into user, Windows reports interrupts as `interrupt` not `irq`,
    etc.). If you display a "% in kernel" rollup, decide whether to
    include the platform-specific kernel-time buckets and apply the
    same rule per OS.

---

## 11. Top CPU per-process % is per-core, not system-wide

- **Decision (2026-05-21).** No agent change. The agent ships
  `cpu_percent` as psutil returns it natively, which for per-process
  values is **percent of a single core** (range 0 to `cpu_count * 100`).
  This is the same on Linux and Windows; not a Windows-specific issue,
  but surfaced while validating the dashboard against the new Windows
  host.
- **Context.** On the dashboard today:
  - "CPU Usage" card uses `psutil.cpu_percent()` (system-wide, 0-100%).
  - "Top CPU" rows use per-process `cpu_percent` (per-core, can exceed
    100% if the process is multi-threaded across cores).
  These are different units, so on a 4-core box you can see "CPU Usage
  5%" while "fivenines-agent" reads 11.4% in Top CPU. Math checks out
  (11.4 / 4 ≈ 2.85% of total system), but operators read the two
  numbers as if they were comparable.
- **Agent change.** Intentionally none. Keeping raw per-core values
  preserves a useful signal — a process reading 600% on an 8-core box
  is occupying 6 cores fully, which is more informative than just
  "75% of total". The backend can derive normalized values if it wants.
- **Backend TODO.**
  - Choose one of these UI patterns and apply consistently:
    1. **Normalize to system-wide.** Divide each `cpu_percent` by
       `cpu_count` (which the agent already reports under the `cpu`
       collector). Cap at 100%. Then the Top CPU row matches the donut.
       Loses the "this process saturates N cores" signal.
    2. **Label the unit.** Keep the per-core value but tag it visually
       (e.g. `11.4% / 4 cores` or `2.85% system`). Preserves the signal
       but takes more screen space.
    3. **Two columns.** Show both `% per-core` and `% system` in the
       Top CPU table. Most explicit but heaviest UI.
  - Recommendation: option 1 (normalize). Casual users will be confused
    by raw per-core %, and power users can dig into `View metrics →` for
    the unnormalized data.

---

## 10. "KERNEL" card on the dashboard is misleading on Windows

- **Decision (2026-05-21).** No agent-side change - the payload already
  carries the right data. This is purely a dashboard relabeling /
  rerouting problem to call out.
- **Context.** The dashboard currently shows a card labelled "KERNEL" with
  value `uname.release`. On Linux that's the kernel version, e.g.
  `6.5.0-21-generic`. On Windows it's `"10"` — the NT kernel major version
  — because Microsoft has frozen the NT kernel at 10 since 2015. Windows
  10, 11, Server 2019/2022/2025 all report NT 10. So `KERNEL: 10` is
  technically correct and almost useless to the operator.
- **Agent change.** None. The agent sends:
  - `uname.system` = `"Windows"` (OS family marker)
  - `uname.release` = `"10"` (NT kernel major)
  - `uname.version` = e.g. `"10.0.26100"` (NT full build - this is the
    useful number; 26100 is Server 2025, 22631 is Win11 23H2, etc.)
  - `uname.machine` = `"AMD64"`
  - `user_context.os_family` = `"windows"`
  - `packages.distro` = e.g. `"windows:Microsoft Windows Server 2025"`
    (constructed in `packages.py::get_distro()` from `platform.win32_ver()`)
- **Backend TODO.** On a host where `uname.system == "Windows"` (or
  equivalently `user_context.os_family == "windows"`), do **one** of:
  1. Hide the "Kernel" card entirely. The NT kernel version isn't useful
     to most Windows operators - they care about the Windows product
     version, which is shown on the OS card (if there is one).
  2. Repurpose the card: change the label to "Windows build" and show
     `uname.version` (e.g. `10.0.26100`) instead of `uname.release`
     (`10`). The build number uniquely identifies the Windows release
     channel (Server 2025 = 26100, Win11 23H2 = 22631, ...).
  3. Combine both into a single "OS" card that reads from `packages.distro`
     stripped of the `windows:` prefix (e.g. "Microsoft Windows Server 2025").

  Either way: on Linux, behavior is unchanged - keep showing the real
  kernel version from `uname.release`.

---

## 9. PID 0 ("System Idle Process") filtered from processes payload

- **Decision (2026-05-21).** The processes collector drops PID 0
  unconditionally. On Windows that pseudo-entry is "System Idle Process",
  which represents CPU time the cores spent doing *nothing* and routinely
  reports ~(cpu_count * 100)% CPU. Including it in the payload made it
  dominate every "Top CPU" view on the dashboard - inverse of useful. On
  Linux PID 0 is the kernel scheduler and not exposed via /proc, so the
  filter is a no-op there.
- **Agent change.** `fivenines_agent/processes.py` skips `proc.pid == 0`
  before calling `as_dict()`. Test in `tests/test_processes.py`.
- **Backend TODO.**
  - No payload-shape change - the field still arrives as a list of
    process dicts, just without PID 0 for Windows hosts.
  - If the dashboard had any defensive code to skip "System Idle Process"
    client-side, it can be removed (we now ship clean data).
  - If you want a top-line "system idle %" metric on Windows, derive it
    from `100 - cpu_usage` rather than from a process row.

---

## 8. MSI installer download URL (post-publication)

- **Decision.** Windows installer is published as a single MSI:
  `fivenines-agent-windows-amd64.msi`. Mirrored to
  `https://releases.fivenines.io/latest/fivenines-agent-windows-amd64.msi`
  and attached to the GitHub Release for the corresponding tag.
- **Backend TODO.**
  - Add a "Windows (x64)" entry to the install instructions page,
    pointing at the MSI URL.
  - One-liner for the docs: `msiexec /i fivenines-agent-windows-amd64.msi TOKEN=<token> /qb`
    (with optional `SERVICEACCOUNT=...` / `SERVICEACCOUNTPASSWORD=...`
    overrides for operators who pre-stage accounts).
  - SmartScreen will warn until Azure Trusted Signing is wired in — note
    that in the docs ("Click 'More info' → 'Run anyway' on the SmartScreen
    dialog. Signing is coming soon.").

---

## How to use this doc

1. New Windows-only decision lands in the agent → add an entry here.
2. When the backend implements an entry, mark it with `~~strikethrough~~`
   on the **Backend TODO** lines that are done, or drop the entry once
   fully resolved.
3. Entry numbers don't change once assigned — append new ones at the end.
