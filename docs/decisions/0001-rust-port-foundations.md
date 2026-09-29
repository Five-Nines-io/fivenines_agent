# 0001 -- Rust port foundations

- Status: proposed
- Date: 2026-09-29
- Tracking: #173 (Phase 0 "Decision record" of #169)
- Inputs: the Go and Rust prototypes and their harness on
  `experiments/agent-rewrite-prototypes` (7de6404), a memory re-measurement
  made for this record (section 3), and an inventory of the Python agent at
  v1.20.1 (86f9857)

This record settles the questions every later step of #169 depends on:
platform scope and order, glibc vs musl, toolchain and MSRV, the concurrency
model, libvirt, Windows, and how long the Python and Rust agents live side by
side. Anything not listed here is left to the step that owns it (last
section).

## Decisions at a glance

| # | Question                     | Decision |
|---|------------------------------|----------|
| 1 | Where the code lives         | This repository, one Cargo workspace under `rust/` |
| 2 | Platform scope and order     | GA = today's matrix plus armv7 and i686. Linux (glibc + musl; x86_64, aarch64, armv7, i686), then Synology, then Windows |
| 3 | glibc or musl                | Both, on every architecture: each host gets the libc it runs, as the installers already choose. glibc build dynamically linked, floor 2.17; musl build fully static |
| 4 | Toolchain and MSRV           | Exact stable version pinned in `rust-toolchain.toml`; MSRV = that version; never below 1.93 |
| 5 | Concurrency                  | Synchronous code on std threads, same thread layout as today. tokio only inside an SDK that needs it, current-thread runtime only |
| 6 | libvirt                      | Our own client for the libvirt RPC protocol, local unix socket only. No C library |
| 7 | Windows                      | After Linux GA; the runtime must compile for Windows from the first commit |
| 8 | Side-by-side support         | Python stays in maintenance for 12 months after each platform's Rust GA |
| 9 | Python bugs found by the port | Fixed in Python first; the harness requires exact equality |

## 1. Where the code lives

**Decision.** In this repository, as one Cargo workspace under `rust/`
(`Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`).

**Why.**
- Both agents treat the contract fixtures in `tests/fixtures/` as the source
  of truth.
- The differential harness runs both agents from one commit.
- The installers, the systemd unit, the SELinux policy and the signing
  pipeline have to serve both agents during the transition.
- A change to a payload and its fixture lands in one PR.

**Consequences.**
- CI jobs are path-filtered, except the harness, which runs whenever either
  agent or a fixture changes.
- The ASCII-only rule and the security checks cover `rust/` too. The CI
  ASCII check in `build-release.yml` matches only `*.py`, `*.toml`, `*.yml`,
  `*.json` and `*.sh` files today; the workspace step adds `*.rs`.

## 2. Platform scope and order

**What ships today.**
- Linux glibc, x86_64 and aarch64. Built on manylinux2014, so the floor is
  glibc 2.17 / CentOS 7, and `centos:7` is still in the distro matrix.
- Linux musl, x86_64 and aarch64. Alpine 3.19+.
- Synology DSM 7, x86_64 and aarch64. This is the glibc build without
  libvirt, proxmoxer, NVML or the watchdog module.
- Windows x64, as an MSI: Windows 10/11 and Server 2019+.
- There is no 32-bit, armv7, macOS or FreeBSD artifact.

**Decision.** GA requires parity with that matrix, plus two new Linux
architectures, armv7 and i686, in this order:

1. Linux x86_64, aarch64, armv7 and i686, glibc and musl builds together.
   The harness and the distro matrix run on Linux first.
2. Synology DSM 7: the Linux glibc binary in an SPK. Only the packaging
   changes; the per-module exclusions go away because Rust has no per-module
   bundle.
3. Windows x64 (section 7).

armv7 and i686 gate GA like the other two architectures, so they need what
x86_64 and aarch64 already have:
- a mapping in every installer and update script (root, user and UNRAID),
  as `armv7l` and `i686`/`i386`;
- distro jobs in the matrix, run under QEMU user emulation, for both
  libcs;
- the same harness parity as x86_64 and aarch64.

Out of scope: macOS, FreeBSD, Windows arm64, 32-bit Windows.

**Why.** The port promises the same payload from a smaller agent. armv7 and
i686 are added now because the Rust build makes them cheap to produce (tier 2
targets, one matrix row per libc), and because the installers are rewritten
for the Rust artifacts anyway; they are the only platform widening in the
port. They carry their own class of bugs (section 5, counters), which the
harness has to catch on those targets, not only on 64-bit hosts.

**Found while taking the inventory.** The root installers
(`fivenines_setup.sh`, `fivenines_update.sh`) send every `uname -m` other
than `aarch64` to the amd64 artifact. An armv7l or i686 host therefore
downloads a binary it cannot execute. The user-mode scripts already reject
unknown architectures. This should be fixed in the current installers now,
independently of the port: until the Rust artifacts exist, such a host
should be refused with a clear message rather than handed a binary it
cannot run (#170).

## 3. glibc or musl

**Facts.**

*Name-service lookups that reach the payload:*
- `user_context.username`, `groupname` and `groups`, resolved once at startup.
- `processes[].username`, resolved for every process on every tick (psutil
  calls `pwd.getpwuid` and falls back to the uid as a string).
- On glibc these lookups go through NSS: SSSD, LDAP, winbind and nss-systemd
  (`DynamicUser=`).
- musl reads only `/etc/passwd` and `/etc/group`, plus nscd if it is running.

*Hostname resolution:*
- The API host and `ip.fivenines.io` bypass libc: dnspython reads
  `/etc/resolv.conf` itself, so the libc choice does not affect them.
- Every other host goes through `getaddrinfo`, which means NSS on glibc. That
  covers ping targets, the redis, memcached, php-fpm, PostgreSQL and MQTT
  hosts, and the HTTP collector URLs.

*Native code loaded at runtime:*
- NVIDIA ships NVML only as a shared library linked against glibc. pynvml
  loads it through ctypes; the Rust equivalent, nvml-wrapper, loads it through
  libloading.
- A static musl binary cannot `dlopen` at all.

*Memory, re-measured.* The prototype READMEs give RSS only. RSS counts the
pages of `libc.so`, `ld.so` and `libgcc_s` that every other process on the
host already maps. `bench/measure.sh` samples PSS too, so both prototype
builds were measured again with the `procs` profile, reading `smaps_rollup`
once the agent was steady (values in kB):

| build          | Rss  | Pss  | Private_Clean (own text) | Private_Dirty (heap, stacks) | Shared_Clean (libc, ld.so, libgcc_s) |
|----------------|-----:|-----:|-------------------------:|-----------------------------:|-------------------------------------:|
| glibc, dynamic | 4460 | 3480 | 2112                     | 972                          | 1376                                 |
| musl, static   | 2472 | 2468 | 2056                     | 412                          | 4                                    |

Setup: rustc 1.98.1 (bundled musl 1.2.5), an aarch64 Linux VM with 6 vCPUs,
the prototype at 7de6404, 1s interval.

The `measure.sh` summaries of the same builds agree: glibc 4.8 MB RSS /
3.4 MB PSS, musl 2.1 / 2.4, with no difference in CPU. (musl's RSS reads
below its PSS there because `VmRSS` in `/proc/<pid>/status` is only
approximate; `smaps_rollup` is exact.)

Very few processes mapped libc in that VM, so the glibc PSS above is an upper
bound. On a real host the shared part tends to zero, and the actual difference
is the private heap: about 0.56 MB.

**Decision.** Ship both builds, on every architecture. Each host gets the
libc it runs, which is the choice `detect_libc()` in the installers already
makes:

- **glibc hosts** (every glibc distribution, and Synology):
  - Dynamically linked against glibc, floor 2.17 (armv7: see consequences).
  - Links only glibc's own libraries, plus `libgcc_s` for unwinding.
  - No bundled `.so`, and no `LD_LIBRARY_PATH` to strip from children.
- **musl hosts** (Alpine): fully static, using the musl that Rust bundles.

**Why.** Parity comes from the construction: each Rust build inherits the
name-service and resolver behavior of the Python build it replaces, and the
Alpine build is musl already. armv7 and i686 have no Python build to match,
so they follow the same rule: a glibc host gets glibc names.

musl everywhere would save about half a megabyte, at two costs:
- usernames would become uids on every LDAP, SSSD or DynamicUser host;
- NVIDIA monitoring would disappear.

Both would still produce well-formed payloads with wrong content, which is
exactly the kind of divergence constraint 1 of #169 exists to catch.

**Consequences.**
- CI checks the glibc floor on the binary itself: no symbol may require a
  `GLIBC_` version above 2.17. The Python build never had this check. The
  `centos:7` distro job stays.
- The glibc build runs in a glibc 2.17 sysroot: the digest-pinned
  manylinux2014 builder images already exist, on native x86_64 and aarch64
  runners, and manylinux2014 also has an i686 image that runs on the x86_64
  runner. rustup and rustc run there, because Rust's own host floor is also
  glibc 2.17 / kernel 3.2. There is no manylinux2014 image for armv7, so the
  release pipeline step sets the armv7 glibc floor and how it is built
  (section 4); the same symbol-version check then enforces it.
- The static musl binary no longer depends on the host's musl. The Alpine
  3.19 floor, which came from the Python build's `pwritev2`, disappears. It is
  lowered only once the distro matrix tests an older Alpine.
- `call_bounded` starts one thread per collector call, and glibc's
  per-thread malloc arenas handle that pattern differently from musl's
  allocator. The RSS soak test covers the glibc artifacts as well as the
  musl ones.

**Reopen if** a platform we must support has no usable glibc floor.

## 4. Toolchain and MSRV

**Decision.**
- `rust/rust-toolchain.toml` pins an exact stable release (1.98.1 as of this
  writing), with rustfmt, clippy and the release targets. Edition 2024.
- The MSRV is the pinned version, declared once as the workspace
  `rust-version`. The agent ships only as binaries built by our CI, so an MSRV
  below the pin would buy nothing: it would cost a CI job and cap our
  dependency versions.
- The pin changes only in a dedicated PR that runs the full CI, the harness
  and the RSS soak test. It never moves implicitly through a builder image's
  `latest` tag.
- A version bump must stay within these floors:
  - **Rust 1.93 or later**, whose musl targets bundle musl 1.2.5. The DNS
    resolver rewrite in musl 1.2.4 (TCP fallback, large responses) matters to
    a static agent that resolves user-configured hosts.
  - **glibc 2.17 / kernel 3.2**, the linux-gnu floor since Rust 1.64. A Rust
    release that raises it would drop CentOS 7, which is a platform decision,
    not a toolchain chore.
  - **Windows 10**, the Windows floor since Rust 1.78. The supported list
    (Windows 10/11, Server 2019+) already meets it.
- Cross-compilation:
  - x86_64, aarch64 and i686 build on native runners (x86_64 and aarch64
    already exist in `build-release.yml`; i686 builds in a 32-bit container
    on the x86_64 runner).
  - armv7 has no native runner, so it is cross-compiled: cargo-zigbuild or a
    pinned cross sysroot, chosen by the release pipeline step. A zig
    version, if used, is pinned exactly.
  - Every release artifact goes through the RSS soak test: with zig 0.16.0,
    the linked musl never freed memory.

## 5. Concurrency

**Facts.** The Python agent runs no asyncio. Its threads are:
- the main loop, which runs every collector in sequence;
- the synchronizer;
- the log uploader and the image inventory uploader;
- one paho network thread per MQTT broker;
- a per-tick SNMP pool (at most 10 threads, whose polls can outlive the tick);
- a systemd drilldown pool (at most 10 threads, joined within the tick);
- `call_bounded` workers: sudo commands, the libvirt probe and io_topology.

**Decision.**
- The agent is synchronous, uses std threads, and keeps the Python agent's
  thread layout.
- The collection loop runs collectors in sequence. Each collector call goes
  through `call_bounded`, which gives each call its own thread, a deadline,
  single-flight per name and `catch_unwind`. That also delivers the per-collector
  bound listed as P3 in TODOS.md.
- The agent's own code uses no async runtime.
- An async-only dependency is allowed only if all of this holds:
  - it sits behind a module boundary that owns one current-thread tokio
    runtime;
  - the runtime is built once and driven with `block_on`;
  - it is called through `call_bounded`.
- No multi-threaded runtime is allowed anywhere. CI fails if tokio's
  `rt-multi-thread` feature appears in the dependency graph.

| Python dependency          | Rust                                                              | Async runtime |
|----------------------------|-------------------------------------------------------------------|---------------|
| psutil                     | Our own /proc and /sys readers, following psutil 7.2.1 (constraint 2) | none |
| requests, urllib3, certifi | ureq 3 with rustls and webpki-roots (the Mozilla bundle, like certifi); system roots where Python uses them today (pg8000, paho) | none |
| dnspython (API host)       | Chosen in the synchronizer step: a minimal stub resolver or hickory | none, or current-thread |
| docker-py                  | HTTP/1.1 over the unix socket with our own string-typed models, **not bollard** (below) | none |
| pg8000                     | Chosen in its step: the `postgres` crate (a blocking wrapper over tokio-postgres) or a minimal wire client | current-thread at most |
| paho-mqtt                  | Chosen in the mqtt step                                           | current-thread at most |
| pynvml                     | nvml-wrapper (libloading); glibc build only                       | none |
| libvirt-python             | Our own RPC client (section 6)                                    | none |
| proxmoxer                  | ureq                                                              | none |
| systemd-watchdog           | An `sd_notify` datagram, written directly                         | none |

The prototype ruled out bollard for three reasons:
- Its models are closed enums, so a container state it does not know turns
  the whole host's `docker` key into `null` (constraint 4).
- It sends unversioned request paths.
- Its timeout panicked outside a runtime context.

**Why synchronous.**
- The collectors' work is blocking syscalls on /proc and /sys. Async has
  nothing to offer there: tokio would move them to `spawn_blocking`, which is
  the same thread.
- `run_privileged` must be able to abandon a subprocess that may never
  return, and only an OS thread can be abandoned safely.
- The collection loop is sequential by design under `WatchdogSec=90`.
- The prototype ran on 3 threads; the Go runtime alone used 15 to 19.

**Consequences.**
- The release profile keeps `panic = "unwind"` and never `"abort"`. With it,
  a panic costs one collector a `null`; the prototype confirmed this when
  bollard's timeout panicked.
- **Mutex poisoning.** A collector that panics while holding shared state
  poisons the lock, and every later `.lock().unwrap()` panics too. The
  prototype's `processes` and `docker` state would turn one panic into a
  `null` on every tick until the agent restarts. So shared state must either
  recover the guard (`PoisonError::into_inner`) and reset what it protects,
  or use a lock that cannot be poisoned.
- An abandoned worker can still hold shared state. Single-flight per name
  protects the next tick only if every path into that state goes through the
  same name.
- Every counter is `u64`. Python integers are unbounded, and `usize`
  truncates on the 32-bit targets (armv7, i686). Values above 2^53, such as docker's
  `system_cpu_usage`, stay integers in the JSON.

## 6. libvirt

**Facts.**
- `qemu.py` makes about 15 read-only calls:
  - connection: open read-only, type and version (debug only), node info,
    list all domains;
  - per domain: state, info, max vCPUs, CPU stats, vCPUs, memory stats, XML
    description, block stats and interface stats.
- The URI allowlist already limits it to local unix sockets
  (`qemu:///system`, `qemu:///session`, `qemu+unix` with a socket in a libvirt
  run directory).
- The glibc build bundles libvirt 6.10.0 and libtirpc, built from source with
  every driver disabled: a socket client and nothing else. Alpine uses the
  system libvirt. Windows and Synology have no qemu collector.
- The collector's own libvirt calls have no timeout; only the 3s probe is
  bounded.
- Much of the allowlist exists to fence behaviors of the C client itself:
  - transports that run commands (`ssh`, `ext`);
  - `LIBVIRT_DEFAULT_URI` and `libvirt.conf`;
  - autostarting the session daemon, disabled with `LIBVIRT_AUTOSTART=0`.

**Decision.** Speak libvirt's remote RPC protocol ourselves, over the local
unix socket only, implementing only the procedures the collector uses.
- No libvirt C library, whether linked or loaded with `dlopen`.
- No third-party pure-Rust crate: the candidates found (libvirt-rpc,
  libvirt-pure) are early-stage and async, and neither passes the dependency
  bar.

**Why.**
- It is the only option that keeps both builds a single file with no bundled
  `.so`. Linking the C library brings back:
  - bundling libvirt, libtirpc, libxml2 and gnutls;
  - `LD_LIBRARY_PATH` in child processes;
  - libvirt's own threads.
- The allowlist becomes structural: the client has no TLS, SSH or `ext`
  transport to refuse, reads no `libvirt.conf` and cannot autostart a daemon.
  No environment variable needs setting, and there is no parse to keep in step
  with libvirt's.
- Every read gets a socket timeout, which today's calls do not have.
- Loading the host's `libvirt.so.0` with `dlopen` would remove the bundling,
  but only on glibc, and it would keep every C-client behavior listed above.
- The remote protocol is also how today's bundled 6.10 client talks to
  current daemons.

**Consequences.** The qemu step owns:
- XDR encoding for about 15 procedures;
- the read-only connect and authentication handshake: none, or polkit on the
  read-only socket;
- libvirt's socket selection for `qemu:///system` and `qemu:///session` with
  `mode=auto|direct|legacy`: the monolithic `libvirt-sock-ro` versus the
  modular `virtqemud-sock-ro`, and `$XDG_RUNTIME_DIR` for session. This
  selection is parity-critical and is tested against both daemon layouts.

qemu has no contract fixture yet, so its step first writes one from the
Python agent's output.

**Reopen if** real hosts set `auth_unix_ro = "sasl"`. SASL is the one
handshake the C client would give us for free.

## 7. Windows

**Facts.**
- Packaging: an MSI built with WiX 5, and WinSW (.NET 4) as the service
  wrapper.
- Windows-only collection:
  - `disk_health` (WMI, via PowerShell);
  - `handle_count` (PDH);
  - the Uninstall-registry software inventory;
  - Windows branches in `cpu`, `network` and `env`.
- The Rust prototype does not compile for Windows (10 errors: `nix`,
  `std::os::unix`, and signal-hook's iterator).

**Decision.**
- Windows ships after Linux GA, as its own Phase 3 step. Until then the Python
  agent remains the Windows agent.
- From the first workspace commit, CI runs `cargo check` and clippy for
  `x86_64-pc-windows-msvc` on the runtime: loop, synchronizer, config, queue
  and bounded calls. Unix-only code sits behind `cfg(unix)`, so doing Linux
  first cannot bake Unix assumptions into the runtime.

**Why.** Windows shares the runtime but almost none of the collection code or
the packaging. Its collector set is small enough to port in one step once the
runtime is proven on Linux.

The Windows step decides whether the binary integrates with the Service
Control Manager itself, which would remove WinSW and its .NET 4 dependency.

## 8. Python and Rust side by side

**Facts.** The agent never updates itself. Updates happen only when someone
runs them:
- Linux: the operator runs the update scripts.
- Windows: the MSI is re-run.
- Synology: the SPK is installed by hand.
- UNRAID: the binary already on flash is relaunched.

So an installed Python agent keeps running until its operator acts, whatever
this record decides.

**Decision.**
- **Before a platform's Rust GA.** Python is the shipping agent there and
  still gets features. A new collector lands in Python first, with its
  contract fixture, and that collector's Rust step reproduces the fixture.
  Once a collector's Rust step has closed, any PR that changes its payload in
  Python must change the Rust side in the same PR. The differential harness
  fails otherwise, so CI enforces this, not process.
- **At GA, per platform.**
  - Installers and update scripts install the Rust agent.
  - The update script migrates a Python install in place; the state files are
    compatible (Phase 3).
  - The Rust GA is the next major version (2.0.0) on the same version line, so
    every existing version comparison keeps working.
- **After GA.**
  - The Python agent for that platform stays in maintenance for 12 months:
    security fixes and fixes that keep its payload valid, no new collectors.
  - Its last release stays downloadable, for rollback.
  - After that, its builds stop. The README states the date from GA onward.
  - Payloads are identical, so nothing needs retiring on the receiving side.
    An old Python agent keeps working after its end of support; it just
    stops getting fixes.

**Why 12 months.** Updates are started by operators, so the window exists for
them, not for us. It is the one number in this record that the Phase 4 beta's
version distribution should confirm or change before GA.

## 9. Python bugs found by the port are fixed in Python first

**Decision.** When the harness or a port shows that the Python agent is
wrong (rather than the port), the fix lands in Python first, with its test and
fixture. The Rust port then reproduces the fixed behavior. The harness stays
an exact comparison, with no list of known differences.

**Why.** A list of known differences is where real divergences hide. And the
fix reaches today's hosts months before the Rust agent does.

Found while preparing this record:
- `vm_vm_uptime_seconds_total` is always 0. `_get_vm_uptime` reads
  `dom.info()[5]`, but `virDomainGetInfo` returns five fields.
- The qemu collector's libvirt calls have no timeout, so one VM with a stuck
  QEMU monitor can stall the tick past `WatchdogSec` (#171).
- The root installers map every unknown architecture to amd64 (section 2,
  #170).
- Child processes inherit the host locale: `get_clean_env` sets no `LC_ALL`,
  and only `dpkg-query` and `rpm` force `C`. smartctl formats `User
  Capacity`, which is shipped verbatim as `total_capacity`, with the locale's
  thousands separator (#172). Until Python changes this, parity means the
  Rust command runner passes the same environment.

## Left to later steps

- Crate layout, lint set, coverage tool and threshold, and the cargo-deny /
  cargo-vet policy: the workspace and CI step.
- The API host's DNS client (it must match dnspython's behavior: reads
  `/etc/resolv.conf` once, A then AAAA, TTL cache flushed on any failure):
  the synchronizer step.
- The PostgreSQL and MQTT clients: their steps, within section 5.
- How the Windows service is run: the Windows step.

## References

- Prototypes, harness and the original measurements:
  `experiments/README.md` on `experiments/agent-rewrite-prototypes`
- Rust linux-gnu floor, glibc 2.17 / kernel 3.2 (Rust 1.64):
  https://blog.rust-lang.org/2022/08/01/Increasing-glibc-kernel-requirements/
- Rust Windows floor, Windows 10 (Rust 1.78):
  https://blog.rust-lang.org/2024/02/26/Windows-7/
- musl 1.2.5 in Rust's musl targets (Rust 1.93):
  https://blog.rust-lang.org/2025/12/05/Updating-musl-1.2.5
- nvml-wrapper loads NVML at runtime: https://docs.rs/nvml-wrapper
