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
- **Auto-enable in backend config (no UI toggle).** Unlike Linux SMART
  (which needs `sudo smartctl`, per-host operator setup, and is therefore
  shown as a beta opt-in checkbox on the "Storage Health" settings card),
  `disk_health` on Windows uses WMI APIs built into the OS (Server 2012+,
  Win 8+) AND our MSI grants the necessary namespace read permission to
  the service account automatically via the `DelegateWmiStorageNamespace.ps1`
  custom action. There is no operator setup. The backend should therefore
  set `disk_health: true` in the config response unconditionally for any
  host whose payload reports `capabilities.disk_health == true`.
  **Do not add a Windows toggle to the Storage Health UI section** — it
  would be a checkbox that does nothing meaningful (everything Windows
  needs is granted at install time). Same logic applies to
  `software_inventory`: enable when capability is true, no UI toggle.
- **Backend TODO.**
  - In the per-host config builder, when responding to `/collect` for a
    Windows host: if `capabilities.disk_health == true`, include
    `disk_health: true` in the config. Same for `software_inventory`.
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
  - On Windows-host pages, hide the "Storage Health" settings card
    (SMART / RAID checkboxes) entirely — that card is Linux-only.

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

## 14. Package security scanner on Windows: registry-sourced, incomplete by design

- **Decision (2026-05-21).** The Windows agent participates in the existing
  package security scan flow (`/packages` endpoint), but the data shape
  and coverage differ enough from Linux that the backend's CVE-matching
  logic needs Windows-specific handling. No agent-side change planned;
  this is a backend coordination + Phase 2 follow-up item.
- **What the agent ships on Windows.**
  - Source: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
    plus the `WOW6432Node` redirect (32-bit apps on 64-bit Windows).
  - Per entry: `{name: <DisplayName>, version: <DisplayVersion>}`
  - Entries with no `DisplayName` are skipped (mostly system updates and
    hidden components - see below).
  - `distro` field set to `"windows:<release>"` (e.g. `"windows:2025server"`).
  - Same delta-by-hash mechanism as Linux: SHA256 of the sorted list,
    only re-shipped when changed.
- **What the agent DOES NOT ship on Windows (gaps).**
  1. **Windows OS updates / hotfixes.** KB articles (e.g. `KB5043076`)
     are installed via the Servicing Stack, not via the Uninstall
     registry. They're queryable via `Get-HotFix` / `wmic qfe` / WMI
     `Win32_QuickFixEngineering`. Half of Windows-relevant CVEs are in
     the OS itself, so without these the scanner has a big blind spot.
     **Tracked in [issue #61](https://github.com/Five-Nines-io/fivenines_agent/issues/61).**
  2. **MSU bundles and feature-on-demand packages.** Same story - not
     in the Uninstall hive.
  3. **System-bundled software with inconsistent registration.**
     .NET Framework versions, PowerShell, IIS modules - some have
     Uninstall entries, some live in their own registry trees, some
     report version only via WMI. Coverage is best-effort.
  4. **Per-user installs (HKCU).** We only read HKLM. User-scope
     installs from a non-service-account user won't appear. For the
     monitoring agent this is correct - service accounts shouldn't
     see other users' software - but it's a gap relative to the
     "everything installed" intuition.
- **Naming and versioning differences vs Linux.**
  - **Linux**: package-manager names (`openssl`, `libc6`, `nginx-full`)
    with distro-specific version strings that include backport patch
    levels (`1.1.1f-1ubuntu2.20`). CPE matching is mature - distro
    package names map cleanly to known CPE patterns and security
    advisories are published per-distro.
  - **Windows**: vendor display names (`Microsoft Edge`,
    `Google Chrome`, `7-Zip 24.07 (x64 edition)`,
    `Python 3.11.9 (64-bit)`). Version strings are whatever the
    installer wrote to `DisplayVersion` and follow no convention -
    semver, dates, hashes, or empty. There's no Windows equivalent
    of "Debian backports patches into the upstream version string" -
    a Chrome at version `124.0.6367.61` is just that, no
    distro-patch suffix.
- **Backend TODO.**
  - **Accept the Windows payload without choking on the differences.**
    Display names will contain spaces, parentheses, version numbers,
    architecture markers (`(x64 edition)`, `(32-bit)`), and free-form
    vendor branding. Version strings may be empty.
  - **CVE-matching strategy: fuzzy CPE on Windows.** The backend's
    current CPE matcher (presumably built for Linux package names) will
    not work directly. Options:
    1. **Curated mapping table.** Maintain a list of `(display_name_pattern,
       vendor, product)` mappings for the top ~500 Windows applications.
       E.g. regex `^Google Chrome$` → `(google, chrome)`. This is the
       NVD CPE Dictionary approach. Slow to maintain but accurate.
    2. **Vendor parsing heuristics.** Strip trailing architecture
       markers, parenthesized notes, and version numbers from the
       DisplayName; lowercase; tokenize. Match against CPE dictionary.
       Faster to bootstrap but more false positives.
    3. **Hybrid.** Curated mappings for the top-N, heuristic for the
       rest, surface "unmatched" packages in the UI so operators can
       contribute mappings.

    Recommend hybrid. Maintaining a `windows-cpe-mappings.json` file in
    the backend repo is small enough to be tractable.
  - **Surface a "Windows OS updates not tracked" disclaimer** on the
    security tab for Windows hosts, until Phase 2 ships the
    `Get-HotFix`-equivalent collector. Operators will reasonably expect
    the scanner to know about missing Windows Updates.
  - **`distro` matching:** `"windows:<release>"` strings should be
    treated as a single "platform: Windows" bucket for advisory
    lookups - there's no Windows equivalent of per-distro security
    advisories (Microsoft publishes per-product CVEs that apply across
    Windows versions, not per-OS-version advisories the way Debian/RHEL
    do).
  - **UI considerations.**
    - Show package counts side-by-side: a Windows host might report
      150-300 packages where a Debian host reports 1,500-3,000. That's
      expected, not a "scan failure".
    - If you display vendor names, parse them out of DisplayName for
      a cleaner list - "Microsoft Edge" reads better than the full
      DisplayName which might be "Microsoft Edge".

---

## 13. Memory + swap fields are platform-specific

- **Decision (2026-05-21).** No agent change. The `memory` and `swap`
  collectors ship `psutil.virtual_memory()._asdict()` and
  `psutil.swap_memory()._asdict()` as-is. The set of keys varies by
  platform; backend needs to know what to expect on Windows vs Linux
  vs macOS.
- **Context.** Agent payload includes two memory-related sections:
  - `memory` — physical RAM stats (bytes for all size fields, percent
    for `percent`).
  - `swap` — swap/pagefile stats.

### `memory` field availability

| Field | Linux | macOS | Windows | Meaning |
|---|---|---|---|---|
| `total` | yes | yes | yes | total physical memory (excl. swap), bytes |
| `available` | yes | yes | yes | memory that can be handed to processes **without swapping**. **This is the cross-platform "actual free memory" signal** - rely on this, not on `free` |
| `percent` | yes | yes | yes | `(total - available) / total * 100` |
| `used` | yes | yes | yes | informational only; computed differently per platform; `total - free` does **not** necessarily equal `used` |
| `free` | yes | yes | yes | truly free (zeroed) pages. **Not** the same as "available" - on Linux/BSD, file cache counts as free-able but is not in `free`. On Windows, `free` and `available` are equal. |
| `active` | yes (UNIX) | yes | - | currently in use or recently used (still in RAM) |
| `inactive` | yes (UNIX) | yes | - | marked as not used |
| `buffers` | yes (Linux, BSD) | - | - | cache for FS metadata |
| `cached` | yes (Linux, BSD) | - | - | general page cache |
| `shared` | yes (Linux, BSD; psutil >= 4.2.0) | - | - | memory shared between processes |
| `slab` | yes (Linux; psutil >= 5.4.4) | - | - | kernel slab cache |
| `wired` | - | yes (macOS, BSD) | - | memory pinned in RAM, never swapped |

Important quirks:
- `used + available` does **not** necessarily equal `total`. There are
  hidden buckets per OS (kernel reservations, page tables, etc.).
- On Windows, `available == free` (they're the same number from
  `GlobalMemoryStatusEx`).
- On Linux, `available` is the kernel's `MemAvailable` from `/proc/meminfo`,
  which accounts for reclaimable file cache. This is what every modern
  Linux tool (`free -h`, `top`, etc.) shows as "available".

### `swap` field availability

| Field | Linux | macOS | Windows | Meaning |
|---|---|---|---|---|
| `total` | yes | yes | yes | total swap/pagefile size in bytes |
| `used` | yes | yes | yes | swap currently in use, bytes |
| `free` | yes | yes | yes | swap currently free, bytes |
| `percent` | yes | yes | yes | utilization 0-100 |
| `sin` | yes | yes | always `0` | bytes swapped **in** from disk (cumulative since boot) |
| `sout` | yes | yes | always `0` | bytes swapped **out** to disk (cumulative since boot) |

Quirks:
- **Windows: `sin` and `sout` are always `0`.** psutil doesn't have a
  way to extract swap-in/swap-out rates from the Windows kernel. Don't
  build a "swap rate" alert on Windows - the values are not meaningful.
  Use `percent` and `used` deltas instead.
- On Linux/macOS, `sin`/`sout` are cumulative counters - the backend
  computes the rate by differencing two samples.
- Windows "swap" is the pagefile (`pagefile.sys`). It's normal for
  Windows to use the pagefile even when there's free RAM, because the
  Windows memory manager preemptively pages out cold pages. `swap.used
  > 0` is not necessarily a memory-pressure signal on Windows the way
  it would be on Linux.

- **Backend TODO.**
  - For the "Memory" donut/usage chart, use `memory.percent` (cross-
    platform, correctly computed by psutil from `available`).
  - For the breakdown ("used vs cached vs free"), branch by OS:
    - Linux: stack `used` / `buffers` / `cached` / `free`. Add `shared`
      and `slab` if you want a more detailed view.
    - macOS: stack `active` / `inactive` / `wired` / `free`.
    - Windows: only two meaningful buckets - `used` and `free`. Don't
      try to fabricate cache visibility on Windows.
  - For swap charts: show `percent` always. Hide swap-rate charts
    (`sin`/`sout` derivatives) on Windows hosts since the values are
    pinned to 0.
  - For "swap pressure" alerts: only fire on Linux/macOS. On Windows,
    base any equivalent alert on memory `available` and `percent`
    instead.

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
