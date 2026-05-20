# Windows Server Support - Implementation Plan

Status: Planned. Reviewed via `/plan-ceo-review` (HOLD SCOPE) on 2026-05-19.
Branch: `spuyet/windows-server-support`
Next gate: `/plan-eng-review` before implementation.

## Goal

Add Windows support to fivenines-agent: Windows Server 2019/2022/2025 and
Windows 10/11. Driven by specific customer deals currently blocked on it.

## Approach: B - "Solid parity", single full-quality release

Core metrics + Windows-native disk health + software inventory + a signed MSI
installer, shipped as one complete release (no pilot phase; CI is the quality
gate). Deep native collectors (Event Log, IIS, MSSQL, Hyper-V, Defender) are
deferred to Phase 2.

## Core insight

This is not a rewrite. The capability-probe + graceful-skip pattern
(`permissions.py` + `collectors.py`), already proven by the Synology build
variant, IS the OS abstraction. Windows is "another platform where many
capabilities probe false." The work is roughly 80% packaging/ops and 20% code.
No new platform-abstraction layer is introduced - that would be over-engineering
on top of a pattern that already works.

## Scope

In scope:
- Agent runs as a Windows Service and reports core metrics.
- Core metrics: CPU, memory, load, disk I/O, network, partitions, processes,
  ports, file/handle count, temperatures, fans, GPU.
- Windows-native disk health via WMI (`MSFT_PhysicalDisk` / storage reliability
  counters).
- Windows software inventory via the registry Uninstall key.
- Signed MSI installer, Windows Service, Windows CI.

Not in scope:
- Deep native collectors - Event Log, IIS, MSSQL, Hyper-V, Defender (Phase 2,
  see TODOS.md, customer-pull-driven).
- Linux-only collectors - RAID/mdadm, ZFS, fail2ban, Proxmox, QEMU/libvirt.
  They probe unavailable on Windows by design.
- macOS support (considered, deferred - becomes cheap after Windows but no
  current demand).
- Cross-platform enrollment-secret hardening (considered, deferred - the token
  is exposed on the install command line on Linux today too; not a
  Windows-specific regression).

## Decisions register

| ID | Decision |
|----|----------|
| Approach | B - solid parity, single full-quality release |
| Mode | HOLD SCOPE - lock B, review for rigor |
| D8 | `ports.py` rewritten on `psutil.net_connections()` - one cross-OS code path; a regression test pins current Linux output |
| D9 | `SIGHUP` registration guarded with `hasattr()`; Windows uses the existing 5-minute auto-reprobe (no manual refresh) |
| D10 | `files.py` reports the Windows handle count as its OWN metric key - not crammed into `file_handles_used`/`file_handles_limit` (semantically distinct; no "limit" on Windows) |
| D11 | WMI disk-health collector runs in an isolated subprocess with a hard timeout (matches the existing smartctl/mdadm pattern) |
| D12 | Service runs as a dedicated low-privilege account in the "Performance Monitor Users" group |
| D13 | Windows sends a fully Windows-tailored capability set - requires backend coordination before release |
| D14 | `windows-latest` CI runner; the suite runs on both OSes; coverage combined across runners to keep the 100% gate honest |
| D16 | Service wrapper: WinSW - agent stays a plain console app; WinSW gives stdout-to-rotating-file + Event Log lifecycle + auto-restart |
| D17 | Single full-quality release, no pilot |
| D19 | The MSI installer delegates WMI Storage-namespace read access to the low-priv account (so disk health works without full admin) |
| D20 | D17 held - validation via CI only; the `windows-latest` job is therefore the sole quality gate |
| D21 | Token delivered as an MSI hidden property - consistent with today's Linux installer |
| Signing | Azure Trusted Signing - start setup immediately (procurement is on the critical path) |
| D2 (eng) | `agent.py` gets an OS-aware file-handles dispatch so the Windows handle-count metric reaches the payload |
| D3 (eng) | Per-OS CI runs collect coverage; a combine job enforces 100% on the merged report; `make test` gets a per-OS config |

## Architecture

```
                       fivenines-agent (process)
  +---------------------------------------------------------------+
  | agent.py   loop | signals* | static_data | dry-run             |
  |    |                                                          |
  |    +-- permissions.py   <== OS-AWARE PROBE  (the rewrite)      |
  |    |      Linux  : /proc, /sys, sudo -n, sockets               |
  |    |      Windows: psutil-true core, WMI probe, registry probe |
  |    |                                                           |
  |    +-- collectors.py registry --> collectors                   |
  |    |      portable (psutil/pynvml) : cpu mem load io net*       |
  |    |                                 partitions processes      |
  |    |                                 temps fans gpu            |
  |    |      Linux-only (probe false)  : smart raid zfs fail2ban   |
  |    |                                 proxmox qemu packages...  |
  |    |      NEW Windows               : disk-health (WMI)         |
  |    |                                  software-inv (registry)  |
  |    |                                                           |
  |    +-- synchronizer.py  HTTP/gzip/TLS/DNS --> fivenines API     |
  |           [UNCHANGED - already fully portable]                 |
  +---------------------------------------------------------------+
   packaged:  Linux   -> py2exe.sh (manylinux Docker)
              Windows -> NEW build (PyInstaller native, simpler)
   service :  Linux   -> systemd / OpenRC
              Windows -> WinSW wrapper
   * SIGHUP guarded; net*/cpu need real Windows branches (not just psutil)
```

No new cross-module coupling. New collectors plug into the existing registry.

## Change set

Modified shared files (these also ship to Linux/Synology - handle with care):

1. `permissions.py` - OS-aware probes. THE centerpiece. Branch once at the top
   of `_probe_all` (`if is_windows(): return self._probe_windows()`), not 22
   inline ternaries. Windows: core metrics True (psutil works), WMI Storage
   probe for disk health, registry probe for software inventory, Linux-only
   capabilities report an honest "N/A on Windows" reason.
2. `agent.py` - guard `SIGHUP` registration with `hasattr(signal, 'SIGHUP')`.
   Add an OS-aware file-handles dispatch in `_collect_metrics`
   (`agent.py:144-146`): on Windows, collect the handle-count metric under its
   own payload key; the Linux `file_handles_used`/`file_handles_limit` keys are
   not emitted on Windows (D10 + eng-review finding 1).
3. `env.py` - guard `import grp` / `import pwd` with `try/except ImportError`
   (CRITICAL: today these are module-level imports, so the agent crashes at
   import on Windows before anything runs). OS-aware `config_dir()` ->
   `%ProgramData%\fivenines_agent`. Explicit Windows branch in
   `get_user_context` (`getpass.getuser()`, admin check) instead of relying on
   the broad `except`. Add an `is_windows()` / `os_family()` helper here as the
   single OS-detection mechanism, and migrate the existing scattered
   `platform.system()` checks (`files.py:13`, `cpu.py`, `network.py`) onto it
   (folded into the port per the eng-review TODO).
4. `collectors.py` - verify collector modules are import-safe on Windows.
   Eng-review finding: `qemu.py:5-10` and `proxmox.py:14-17` ALREADY guard
   their heavy imports (`libvirt`, `proxmoxer`) with `try/except ImportError`,
   and `env.py` (item 3) is the only unguarded OS-specific import in the
   package. Action: confirm the existing `qemu`/`proxmox` guards hold and
   quick-audit the remaining collector modules - no new guards expected. The
   import-time crash risk is real but concentrated in `env.py`.
5. `ports.py` - rewrite on `psutil.net_connections()`. Validate the output
   contract on BOTH OSes, not just a Linux regression test - psutil's output
   differs from the `/proc/net/tcp` parser (dual-stack, UDP semantics, address
   formatting, ephemeral-port filtering).
6. `files.py` - Windows handle-count metric under its own key.
7. `cpu.py` - Windows `cpu_model` branch (currently returns `"-"` on Windows).
8. `network.py` - Windows branch (currently returns `[]` for any
   non-Linux/non-Darwin OS - network metrics would be empty otherwise).
9. `CAPABILITY_HINTS` + the banner - OS-aware; Windows-tailored capability
   grouping (D13).
10. `pyproject.toml` / `requirements.txt` - a Windows-only dependency group
    (`pywin32`, `wmi`). Ensure the `virtualization` group (libvirt-python,
    systemd-watchdog) is excluded from Windows builds, the way the Synology
    build excludes it.

New:

11. Windows disk-health collector - WMI `MSFT_PhysicalDisk` + storage
    reliability counters, run subprocess-isolated with a hard timeout.
12. Windows software-inventory collector - registry Uninstall key (both the
    64-bit and 32-bit `HKLM` views). Plugs into the existing hash-based delta
    sync in `packages.py`.
13. Windows build script - PyInstaller native (no manylinux, no
    libpython-from-source). Excludes the virtualization deps. Include
    `--hidden-import win32timezone` (a known pywin32 PyInstaller gotcha).
14. WinSW integration - bundled wrapper, service config XML, Event Log source.
15. MSI installer (WiX) - install the binary to `Program Files`
    (admin-write-only); config dir in `%ProgramData%` with a RESTRICTIVE ACL on
    `TOKEN` (inheritance broken; service account + Administrators only); the
    installer delegates WMI Storage-namespace read access to the service
    account (D19); token passed as a hidden MSI property; clean uninstall
    removes the config dir.
16. Windows install/update/uninstall path.
17. CI - `windows-latest` runner in `build-release.yml`. Per-OS jobs run
    `pytest --cov` WITHOUT `--cov-fail-under` (neither OS alone can reach 100%
    - the other OS's branches are unreachable); a combine job merges coverage
    with `coverage combine` and enforces `--cov-fail-under 100` on the merged
    report. `make test` gets a per-OS coverage config so local runs still pass
    and still gate 100% of OS-reachable code (D3). Plus an end-to-end smoke job
    (install MSI -> service starts -> one successful report -> clean uninstall).
18. Tests - Windows-path coverage; the `ports.py` Linux-output regression test.

## Error and rescue registry

| Codepath | Failure | Exception | Rescue | User sees |
|----------|---------|-----------|--------|-----------|
| `agent.py` setup_signals | SIGHUP absent | AttributeError | `hasattr` guard | nothing - agent starts |
| `env.py` import | `pwd`/`grp` absent | ImportError (at import) | `try/except ImportError` guard | nothing - agent starts |
| `env.py` get_user_context | `os.getuid` absent | AttributeError | explicit Windows branch | correct Windows user context |
| `env.py` config_dir | `%ProgramData%` missing | KeyError | `os.environ.get` + fallback | nothing |
| `permissions.py` probes | Linux probes all false | none (silent wrong result) | OS-aware probe rewrite | core metrics actually collected |
| `collectors.py` import | collector imports a missing lib | ImportError (at import) | every module import-safe on Windows | nothing - agent starts |
| Windows disk-health (WMI) | WMI down / COM error | wmi.x_wmi, com_error | catch, log, return None | "disk health unavailable" + reason |
| Windows disk-health (WMI) | query hangs | none (hang) | subprocess isolation + hard timeout | tick completes, disk health skipped |
| Windows sw-inventory | registry key missing / denied | FileNotFoundError, PermissionError, OSError | catch, return empty | "software inventory unavailable" |
| `ports.py` (psutil) | needs admin on Windows | psutil.AccessDenied | catch per-connection, collect visible | ports list (partial without admin) |
| frozen binary | missing hidden import | ModuleNotFoundError | `--hidden-import` + CI smoke test | nothing - caught in CI |
| Windows Service | service fails to start | SCM error (agent not running) | WinSW logs to Event Log | failed state in services.msc |

## Failure modes registry

| Codepath | Failure mode | Rescued? | Tested? | User sees | Logged? |
|----------|--------------|----------|---------|-----------|---------|
| env.py import | pwd/grp ImportError | Y (guard) | Y (windows CI) | nothing | n/a |
| collectors.py import | collector lib ImportError | Y (guards) | Y (windows CI) | nothing | n/a |
| permissions probe | wrong result on Windows | Y (rewrite) | Y | correct metrics | n/a |
| WMI disk-health | hang | Y (subprocess+timeout) | Y (hostile-QA test) | disk health skipped this tick | Y |
| WMI disk-health | service down | Y | Y | "unavailable" + reason | Y |
| ports.py | AccessDenied | Y | Y | partial ports list | Y (debug) |
| MSI install | service running | Y (MSI stops it) | Y (smoke job) | normal upgrade | n/a |
| token file | world-readable in ProgramData | Y (installer ACL) | Y (verify ACL test) | nothing | n/a |

No CRITICAL GAPS remain: every row is rescued and testable. The two import-time
crashes (env.py, collectors.py) are the highest-priority fixes - the agent does
not start without them.

## Critical landmines (do these first / watch closely)

1. `env.py` module-level `pwd`/`grp` import - agent crashes at import. Fix first.
2. `collectors.py` imports all collector modules at load - but `qemu.py` and
   `proxmox.py` already guard their `libvirt`/`proxmoxer` imports. Verify those
   guards hold and quick-audit the rest; the real import crash is `env.py`
   (landmine 1), not the collectors.
3. WMI calls can hang - subprocess isolation + hard timeout, no exceptions.
4. `TOKEN` is world-readable under default `%ProgramData%` ACLs - installer must
   lock it down, and the ACL must survive `_swap_token` rotation.
5. Shared-file edits ship to Linux in the same release - the `ports.py`
   regression test is the safety net.
6. Backend must support the Windows-tailored capability set BEFORE release.
7. Code-signing certificate has procurement lead time - Azure Trusted Signing
   setup must start now, in parallel with all code work.

## Sequencing and critical path

1. NOW, in parallel with everything: start Azure Trusted Signing setup; start
   the backend Windows-tailored-capability work.
2. Import safety: `env.py` + `collectors.py` guards (agent must start at all).
3. Core: `permissions.py` OS-aware probe -> shared-file Windows branches
   (`ports`, `files`, `cpu`, `network`) -> Windows collectors (disk-health,
   software-inventory).
4. Packaging: Windows build script -> WinSW -> MSI (WiX) -> signing.
5. CI: `windows-latest` runner + combined coverage + the e2e smoke job.
6. Release gate (D20 - CI is the only gate): suite green on both OSes, backend
   capability support deployed, signing live.
7. Single combined release.

## Phase 2 (tracked in TODOS.md)

Windows-native service collectors: Event Log (security signal), IIS, MSSQL,
Hyper-V, Defender. Each parallels an existing Linux collector and plugs into
the registry with its own Windows capability probe. Customer-pull-driven.

## Implementation Tasks

Synthesized from the CEO + eng reviews. P1 blocks the release; P2 lands in the
same branch. Effort is human-team / CC-assisted.

- [ ] **T1 (P1, ~3h / ~25min)** - `env.py` - guard `pwd`/`grp` imports, add the `is_windows()` helper, Windows `config_dir()` + `get_user_context`, migrate scattered `platform.system()` checks. Verify: agent imports on Windows; `test_env.py` covers the guard.
- [ ] **T2 (P1, ~1.5d / ~1.5h)** - `permissions.py` - OS-aware `_probe_windows()`: core caps true, WMI Storage + registry probes, Windows-tailored capability set, OS-aware banner. Verify: `_probe_windows()` returns core metrics available.
- [ ] **T3 (P1, ~3h / ~20min)** - `agent.py` - guard `SIGHUP` registration; add OS-aware file-handles dispatch in `_collect_metrics`. Verify: agent starts on Windows, handle-count reaches the payload.
- [ ] **T4 (P2, ~1h / ~10min)** - `collectors.py` - verify `qemu`/`proxmox` import guards hold; quick-audit the rest. Verify: `import collectors` succeeds on Windows.
- [ ] **T5 (P2, ~4h / ~30min)** - `ports.py` - rewrite on `psutil.net_connections()` + **mandatory** Linux-output regression test. Verify: Linux output unchanged; Windows path works.
- [ ] **T6 (P2, ~2h / ~15min)** - `files.py` - Windows handle-count metric under its own key. Verify: handle count emitted on Windows.
- [ ] **T7 (P2, ~3h / ~20min)** - `cpu.py` + `network.py` - Windows branches (`network.py` returns `[]` on Windows today; `cpu.py` returns `"-"`). Verify: real network + cpu_model data on Windows.
- [ ] **T8 (P2, ~1d / ~1h)** - new Windows disk-health collector - WMI, subprocess-isolated with a hard timeout. Verify: disk health on Windows; hung-WMI test.
- [ ] **T9 (P2, ~6h / ~40min)** - new Windows software-inventory collector - registry Uninstall key, reuses the hash delta-sync. Verify: program list on Windows.
- [ ] **T10 (P1, ~1d / ~1h)** - Windows PyInstaller build script, excludes the virtualization dep group. Verify: frozen binary runs `--version`.
- [ ] **T11 (P2, ~1h / ~10min)** - `pyproject.toml`/`requirements.txt` - Windows dependency group (`pywin32`, `wmi`); virtualization group excluded for Windows. Verify: clean Windows install.
- [ ] **T12 (P2, ~6h / ~45min)** - WinSW service wrapper - bundled exe, config XML, Event Log source. Verify: service starts/stops/restarts.
- [ ] **T13 (P1, ~1.5d / ~1.5h)** - WiX MSI installer - `Program Files`, restrictive `TOKEN` ACL, WMI Storage-namespace delegation, hidden token property, clean uninstall. Verify: install/uninstall lifecycle, ACL set.
- [ ] **T14 (P1, ~6h / ~40min)** - CI - `windows-latest` runner, coverage-combine job, e2e smoke job, `make test` per-OS config. Verify: combined coverage hits 100%.
- [ ] **T15 (P2, ~1d / ~1.5h)** - Windows-path test coverage for every task above, `skipif`-marked by OS. Verify: combined coverage 100%.

External dependencies (not agent-repo code, on the critical path - start now):
- Azure Trusted Signing account setup (procurement lead time).
- Backend support for the Windows-tailored capability set (D13).

## Worktree Parallelization

Two genuinely independent workstreams; CI merges them.

| Lane | Tasks | Modules touched | Depends on |
|------|-------|-----------------|------------|
| 1 - Agent code | T1-T9, T15 | `fivenines_agent/`, `tests/` | T1 first, then T2; rest follow |
| 2 - Packaging | T10-T13 | build script, `windows/`, `pyproject.toml` | - (fully independent) |
| 3 - CI | T14 | `.github/workflows/` | Lanes 1 + 2 |

Execution order:
1. Launch Lane 1 and Lane 2 in parallel worktrees immediately - disjoint directories, zero shared files, clean merges.
2. Inside Lane 1: T1 (`env.py` helper) must land first; T2 (`permissions.py`) second; T3-T9 then proceed, T4-T7 independent of each other.
3. Merge Lanes 1 + 2, then do T14 (CI) last - it needs both the code and the packaging to exist.

Conflict flags: none between Lane 1 and Lane 2 (disjoint paths). Within Lane 1, T3 (`agent.py`) and T4 (`collectors.py` audit) lightly touch the collector registry - sequence T3 after T4 or coordinate.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | clean | HOLD_SCOPE, 21 decisions, 0 critical gaps |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | - | - |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | clean | 3 issues, 0 critical gaps |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | - | n/a - no UI scope |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | - | - |

- **OUTSIDE VOICE:** codex-plan-review ran (gpt-5.5) during the CEO review - caught 2 import-time crashes (`env.py` pwd/grp, `collectors.py` import chain); both triaged and folded into the plan.
- **UNRESOLVED:** 0 decisions across both reviews.
- **VERDICT:** CEO + ENG CLEARED - ready to implement.
