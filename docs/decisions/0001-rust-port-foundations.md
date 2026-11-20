# 0001 -- Rust port foundations

- Status: accepted
- Date: 2026-09-29
- Tracking: #173 (Phase 0 "Decision record" of #169)
- Inputs: the Go and Rust prototypes and their harness on
  `experiments/agent-rewrite-prototypes` (7de6404), memory re-measurements
  made for this record on aarch64 and x86_64 (section 3), and an inventory of
  the Python agent at v1.20.1 (b146ea7), with later fixes noted where they
  change a fact (up to v1.20.4)

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
| 3 | glibc or musl                | Both, on every architecture: each host gets the libc it runs, as the installers already choose. glibc build dynamically linked, floor 2.17, malloc arenas capped; musl build fully static |
| 4 | Toolchain and MSRV           | Exact stable version pinned in `rust-toolchain.toml`; MSRV = that version; never below 1.93 |
| 5 | Concurrency                  | Synchronous code on std threads, same thread layout as today. tokio only inside an SDK that needs it, current-thread runtime only |
| 6 | libvirt                      | Our own client for the libvirt RPC protocol, local unix socket only. No C library |
| 7 | Windows                      | After Linux GA; the runtime must compile for Windows from the first commit |
| 8 | Side-by-side support         | Python stays in maintenance for 12 months after each platform's Rust GA, released from a maintenance branch that never becomes `latest`; installers gain a verified pinned-version mode; the payload names its implementation |
| 9 | Python bugs found by the port | Fixed in Python first; the harness requires equality on recorded inputs, with Python-made text normalized in Python first |

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
- CI jobs are path-filtered, except the harness:
  - it runs on every pull request and is a required status check on main,
    a branch-protection setting the harness step (#176) asks the maintainer
    to make, since no file in the repository can;
  - it filters paths inside the job rather than in `on:`, so the required
    check always reports instead of leaving a pull request on "Expected";
  - it does the work when either agent, a fixture, `pyproject.toml`,
    `poetry.lock`, `rust/Cargo.lock`, `rust/rust-toolchain.toml`, the zig
    or cross-sysroot pin (it chooses the armv7 musl), the harness or a mock
    changes (a lockfile-only psutil bump changes Python
    payloads), and on a weekly schedule.
- The ASCII-only rule and the security checks cover `rust/` too. The CI
  ASCII check in `build-release.yml` matches only `*.py`, `*.toml`, `*.yml`,
  `*.yaml`, `*.json` and `*.sh` files today, and that workflow has no
  `pull_request` trigger. The workspace step adds `*.rs` and runs the check
  on pull requests.
- Neither security check sees Rust today: Bandit is Python-only and the
  CodeQL matrix is `python` and `actions`. The workspace step (#175) adds
  CodeQL for Rust, cargo-deny / cargo-audit and a `cargo` entry in
  Dependabot.

## 2. Platform scope and order

**What ships today.**
- Linux glibc, x86_64 and aarch64. Built on manylinux2014, so the floor is
  glibc 2.17 / CentOS 7, and `centos:7` is still in the distro matrix (for
  x86_64; the aarch64 glibc build is tested on Ubuntu 22.04, Debian 12 and
  Rocky 9).
- Linux musl, x86_64 and aarch64. Documented as Alpine 3.19+; the matrix
  tests Alpine 3.21 only.
- Synology DSM 7, x86_64 and aarch64. This is the glibc build without
  libvirt, proxmoxer, NVML or the watchdog module.
- Windows x64, as an MSI: Windows 10/11 and Server 2019+.
- There is no 32-bit, armv7, macOS or FreeBSD artifact.
- The optional `virtualization` Poetry group (libvirt-python, proxmoxer,
  pynvml, systemd-watchdog) is installed only by the glibc build. The Alpine
  binary therefore ships without proxmoxer and pynvml (libvirt-python is
  added separately), and the Windows binary without pynvml, although both
  still probe `nvidia_gpu`.

**Decision.** GA requires parity with that matrix, plus two new Linux
architectures, armv7 and i686, in this order:

1. Linux x86_64, aarch64, armv7 and i686, glibc and musl builds together.
   The harness and the distro matrix run on Linux first.
2. Synology DSM 7: the Linux glibc binary in an SPK, built without the
   collectors the Python SPK excludes today (qemu, proxmox, nvidia_gpu), so
   the Synology payload stays what Python reports. Adding them later is a
   payload change like any other.
3. Windows x64 (section 7).

armv7 and i686 gate GA like the other two architectures, so they need what
x86_64 and aarch64 already have:
- a mapping in every installer and update script (root and user; UNRAID is
  x86_64 only), as `armv7l` (and `armv8l`, which an arm64 kernel reports
  to a 32-bit personality) and `i686`/`i386`. The mapping follows the
  userland, not only `uname -m`, which names the kernel: 32-bit Raspberry Pi
  OS boots a 64-bit kernel on a Pi 4 or 5, so it reports `aarch64` over an
  armhf userland with no arm64 loader. The #170 fix already refuses that case
  through `getconf LONG_BIT`; the Rust installers send it to armv7 instead
  (and a 32-bit userland on an x86_64 kernel to i686);
- distro jobs in the matrix, run under QEMU user emulation, for both
  libcs;
- the same harness parity as x86_64 and aarch64.

i686 means Rust's baseline for that target: SSE2, i.e. a Pentium 4 or later.
Linux reports `i686` for older CPUs too (Pentium III, VIA C3), where the
binary would die with SIGILL on every restart, so the installers check for
the `sse2` flag in `/proc/cpuinfo` and refuse the host without it.

Out of scope: macOS, FreeBSD, Windows arm64, 32-bit Windows.

**Why.** The port promises the same payload from a smaller agent. armv7 and
i686 are added now because the Rust build makes them cheap to produce
(`i686-unknown-linux-gnu` is a tier 1 target, the other three tier 2; one
matrix row per libc), and because the installers are rewritten
for the Rust artifacts anyway; they are the only platform widening in the
port. They carry their own class of bugs (section 5, counters), which the
harness has to catch on those targets, not only on 64-bit hosts.

**Found while taking the inventory.** Until v1.20.2 (#170), the root
installers sent every `uname -m` other than `aarch64` to the amd64
artifact, which an armv7l or i686 host cannot execute. Every Linux
installer now refuses a host no release has a binary for, including a
32-bit userland on a 64-bit kernel whose `getconf LONG_BIT` prints 32 (a
host without `getconf` is not guessed at), until the Rust artifacts exist.

The Windows gap is a Python packaging bug, not a platform limit. NVIDIA
ships NVML on Windows as `nvml.dll`, which pynvml knows how to load, and the
Windows capability set already probes `nvidia_gpu`. A Windows host with an
NVIDIA GPU therefore reports no GPU metrics today, where a Rust build using
nvml-wrapper would. By section 9 it is fixed in Python first (issue to be
filed). The Alpine gaps change no collected data, only the text of
`capability_reasons` (`pynvml not installed`): the proxmox probe requires a
local Proxmox VE node (`/etc/pve` or `pvesh`), which is never Alpine, and
the Rust musl build has no NVML either, since a static binary cannot
`dlopen` (section 3).

## 3. glibc or musl

**Facts.**

*Name-service lookups that reach the payload:*
- `user_context.username`, `groupname` and `groups`, resolved once at startup.
- `processes[].username`, resolved for every process on every tick when
  `processes` is enabled (psutil calls `pwd.getpwuid` and falls back to the
  uid as a string).
- On glibc these lookups go through NSS: SSSD, LDAP, winbind and nss-systemd
  (`DynamicUser=`).
- musl reads only `/etc/passwd` and `/etc/group`, plus nscd if it is running.

*Hostname resolution:*
- The API host and `ip.fivenines.io` bypass libc: dnspython reads
  `/etc/resolv.conf` itself (once per process) and never reads `/etc/hosts`,
  so the libc choice does not affect them.
- Every other host goes through `getaddrinfo`, which means NSS on glibc. That
  covers ping targets, the memcached, php-fpm, PostgreSQL and MQTT hosts, and
  the HTTP collector URLs (proxmox and a `tcp://` Docker socket included).
  redis always connects to `localhost`.
- The CLI tools the agent runs against a host (net-snmp, mysql, ceph) resolve
  names in their own process, whatever libc the agent uses.

*Native code loaded at runtime:*
- NVIDIA ships NVML only as a shared library linked against glibc. pynvml
  loads it through ctypes; the Rust equivalent, nvml-wrapper, loads it through
  libloading.
- A static musl binary cannot `dlopen` at all.
- Today's Alpine binary does not bundle pynvml (section 2), so the Alpine
  agent has no NVIDIA monitoring either.

*Memory, re-measured.* The prototype READMEs give RSS only. RSS counts the
pages of `libc.so`, `ld.so` and `libgcc_s` that every other process on the
host already maps. `bench/measure.sh` samples PSS too, so both prototype
builds were measured again with the `procs` profile (the core collectors
plus `processes`, no Docker), reading `smaps_rollup` once the agent was
steady (values in kB):

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
is the private dirty memory (heap and stacks): about 0.56 MB here.

That difference grows with the workload. The same binaries as the #169 table
were run again on its 16-core x86_64 host (1s interval, 40 mock containers
for `docker`), reading `Private_Dirty` (heap and stacks, in kB), the one
figure that does not depend on what else shares the pages:

| profile  | glibc                    | glibc, one malloc arena | musl        |
|----------|-------------------------:|------------------------:|------------:|
| `procs`  | 1248 (1460 at 90s)       | 1216 to 1244            | 556 to 572  |
| `docker` | 2940, 3096 at 300s       | 1912 to 1940            | 1092 to 1156 |

- Without Docker, the private difference is 0.6 to 0.7 MB, in line with the
  aarch64 table.
- With Docker, it is about 1.9 MB, and the glibc build is still creeping
  after 5 minutes while the other two are flat. glibc's per-thread malloc
  arenas account for 1.1 MB of it: `glibc.malloc.arena_max=1` removes that
  and leaves about 0.8 MB.

**Decision.** Ship both builds, on every architecture. Each host gets the
libc it runs, which is the choice `detect_libc()` in the installers already
makes:

- **glibc hosts** (every glibc distribution, and Synology):
  - Dynamically linked against glibc, floor 2.17 (armv7: see consequences).
  - Links only glibc's own libraries, plus `libgcc_s` for unwinding.
  - No bundled `.so`, so no `LD_LIBRARY_PATH` of our own to strip from
    children. The Rust command runner still drops the same variables
    `get_clean_env` drops today (`LD_LIBRARY_PATH`, `LD_PRELOAD`, `LIBPATH`,
    the `DYLD_*` pair), operator-set ones included, since no child sees
    them today.
- **musl hosts** (Alpine): fully static, using the musl that Rust bundles
  (or zig's, where section 4 lets zig link armv7).

**Why.** Parity comes from the construction: each Rust build inherits the
name-service and resolver behavior of the Python build it replaces, and the
Alpine build is musl already. armv7 and i686 have no Python build to match,
so they follow the same rule: a glibc host gets glibc names.

musl everywhere would save 0.6 to 0.8 MB of private memory once the glibc
build caps its arenas (consequences), at two costs:
- usernames would become uids on every LDAP, SSSD or DynamicUser host;
- NVIDIA monitoring would disappear.

Both would still produce well-formed payloads with wrong content, which is
exactly the kind of divergence constraint 1 of #169 exists to catch.

**Consequences.**
- CI checks the glibc floor on the binary itself: no symbol may require a
  `GLIBC_` version above 2.17. The Python build never had this check. The
  `centos:7` distro job stays.
- CI also checks the link shape, which the symbol-version check cannot see:
  the glibc artifact's `DT_NEEDED` entries stay within libc, libm,
  libpthread, libdl, librt, the dynamic loader and libgcc_s (a crate that
  pulls in `libssl.so` or `libz.so` fails), and the musl artifact has
  neither `PT_INTERP` nor `DT_NEEDED`.
- The glibc build runs in a glibc 2.17 sysroot: the manylinux2014-based
  builder images already exist, on native x86_64 and aarch64
  runners, and manylinux2014 also has an i686 image that runs on the x86_64
  runner. rustup and rustc run there, because Rust's own host floor is also
  glibc 2.17. There is no manylinux2014 image for armv7, so the
  release pipeline step sets the armv7 glibc floor and how it is built
  (section 4); the same symbol-version check then enforces it.
- The static musl binary no longer depends on the host's musl. The documented
  Alpine 3.19 floor (the current musl binary needs `pwritev2`, which Alpine
  3.18 lacks) no longer applies to it, but it is lowered only once the
  distro matrix tests an older Alpine.
- `detect_libc()` recognizes glibc only when `ldd --version` contains
  `glibc`, which the RHEL family (`ldd (GNU libc) 2.x`) does not print:
  those hosts get glibc from the final fallback today. It also knows only
  the x86_64 and aarch64 musl loaders. The Rust installers detect each libc
  positively: glibc through `getconf GNU_LIBC_VERSION` or its loader, musl
  through `ldd` or its loader (armhf and i386 added). Only a host where
  neither is found gets the static musl build, which runs on any Linux of
  its architecture. An armv7 host gets the glibc build only where the
  armhf loader exists (`/lib/ld-linux-armhf.so.3`), so a soft-float
  userland falls back to musl too.
- `call_bounded` starts one thread per collector call, and glibc binds
  threads to extra malloc arenas that keep freed memory. The glibc build
  caps the arena count with `mallopt(M_ARENA_MAX, ...)` at startup, before
  any thread starts. It does this in the binary, not through
  `GLIBC_TUNABLES`, which every child process would inherit. The release
  pipeline step picks the value; the RSS soak test covers the glibc
  artifacts as well as the musl ones.

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
  - **glibc 2.17 / kernel 3.2** (4.1 on aarch64), the linux-gnu floor since
    Rust 1.64. A Rust release that raises it would drop CentOS 7, which is a
    platform decision, not a toolchain chore.
  - **Windows 10**, the Windows floor since Rust 1.78. The supported list
    (Windows 10/11, Server 2019+) already meets it.
- Cross-compilation:
  - x86_64, aarch64 and i686 build on native runners (x86_64 and aarch64
    already exist in `build-release.yml`; i686 builds in a 32-bit container
    on the x86_64 runner).
  - armv7 has no native runner, so it is cross-compiled: cargo-zigbuild or a
    pinned cross sysroot, chosen by the release pipeline step. A zig
    version, if used, is pinned exactly. A musl artifact linked by zig
    carries zig's musl, not the one Rust bundles, so the musl 1.2.4 floor
    above applies to that zig version too.
  - The cross toolchain includes a C compiler for every target: ring, the
    rustls crypto provider in the prototype, compiles C and assembly (so
    does aws-lc-rs, the alternative).
  - The prototype pinned none of this: it was built with whatever `stable`
    was (1.98.1), and its zig pin exists only as README text.
  - Every release artifact goes through the RSS soak test: with zig 0.16.0,
    the linked musl never freed memory.

## 5. Concurrency

**Facts.** The Python agent runs no asyncio. Its threads are:
- the main loop, which runs every collector in sequence;
- the synchronizer;
- the log uploader and the image inventory uploader;
- one paho network thread per MQTT broker;
- a per-tick SNMP pool (at most 10 threads per tick; a poll can outlive its
  tick, so polls from earlier pools can add to that);
- a systemd drilldown pool (at most 10 threads, joined within the tick);
- `call_bounded` workers: sudo commands, the libvirt probe, io_topology
  and, since v1.20.4, the whole qemu collection. All but the sudo commands
  are single-flight; each timed-out sudo call leaves one thread behind.

**Decision.**
- The agent is synchronous, uses std threads, and keeps the Python agent's
  thread layout.
- The collection loop runs collectors in sequence. Each collector call goes
  through `call_bounded`, which gives each call its own thread, a deadline,
  single-flight per name and `catch_unwind`. That delivers the
  per-collector deadline of the P3 entry in TODOS.md, not its two other
  points: deadlines run in sequence can still add up past `WatchdogSec`,
  and state kept per thread (docker's cached client) would be rebuilt on
  every fresh worker. So:
  - a whole-tick budget under `WatchdogSec` sits above the per-collector
    deadlines and covers the tick's synchronous sends too (the packages
    and systemd inventory syncs can each take about 45s during an API
    outage): once it is spent, the collectors left in that tick report
    `null` without running (the posture of today's docker, openvpn and
    proxmox backups budgets);
  - the watchdog is fed during the sleep between ticks, and a
    server-pushed interval is capped below `WatchdogSec`: today the sleep
    feeds nothing and the interval has no cap, so an interval of 90s or
    more gets the agent killed on every tick;
  - state a collector keeps across ticks belongs to the collector, never to
    the worker thread that happens to run it;
  - these rules change what a stalled or slow tick does (Python blocks
    today, until the watchdog restarts it), so by section 9 they land in
    Python first, as the P3 entry already plans for the per-collector
    bound.
- The agent's own code uses no async runtime.
- An async-only dependency is allowed only if all of this holds:
  - it sits behind a module boundary that owns one current-thread tokio
    runtime;
  - the runtime is built once and driven with `block_on`;
  - it is called through `call_bounded`.
  The one exception is a long-lived connection (MQTT, below): its runtime
  lives on the thread that owns the connection, and only the snapshot read
  goes through `call_bounded`.
- No multi-threaded runtime is allowed anywhere. CI fails if tokio's
  `rt-multi-thread` feature appears in the dependency graph.

| Python dependency          | Rust                                                              | Async runtime |
|----------------------------|-------------------------------------------------------------------|---------------|
| psutil                     | Our own /proc and /sys readers, following psutil 7.2.1 (constraint 2) | none |
| requests, urllib3, certifi | ureq 3 with rustls and webpki-roots (the Mozilla bundle, like certifi); for pg8000 and paho, which use OpenSSL's default verify paths, the store the frozen binaries actually reach is measured in their steps | none |
| dnspython (API host, `ip.fivenines.io`) | Chosen in the synchronizer step: a minimal stub resolver or hickory | none, or current-thread |
| docker-py                  | HTTP/1.1 over the endpoint docker-py reaches today (the unix socket, a `tcp://` `socket_url`, or `DOCKER_HOST` with `DOCKER_TLS_VERIFY` / `DOCKER_CERT_PATH` client certificates), with our own string-typed models, **not bollard** (below). `ssh://` passes the probe but fails at runtime (paramiko is not bundled) and ships `null`; the Rust agent keeps that outcome | none |
| python-dotenv              | `<config_dir>/.env` read into the environment at startup, same grammar (`${VAR}` interpolation), never overriding a variable already set. Python reads it after `CONFIG_DIR` is resolved, so a `CONFIG_DIR` set in `.env` moves `machine_id`, the journal allowlist and the TOKEN swap but not the TOKEN read: the Rust agent keeps that order, or Python fixes it first | none |
| pg8000                     | Chosen in its step: a minimal wire client, or an async client behind the rule above. Not the `postgres` crate as it stands: it builds a runtime per connection, and the collector connects on every tick | current-thread at most |
| paho-mqtt                  | Chosen in the mqtt step. Like paho's network thread, one long-lived thread per broker keeps the connection and its keepalives; only the snapshot read goes through `call_bounded`, since a runtime driven only at tick time would batch messages and corrupt their ages | none, or current-thread on that thread |
| pynvml                     | nvml-wrapper (libloading): glibc and Windows (`nvml.dll`) builds, never musl | none |
| libvirt-python             | Our own RPC client (section 6)                                    | none |
| proxmoxer                  | ureq                                                              | none |
| systemd-watchdog           | An `sd_notify` datagram, written directly                         | none |

bollard is ruled out by what the prototype's docker port found:
- Its models are closed enums: 14 in the responses the prototype parses. An
  unknown value in 10 of them, such as a container state it does not know,
  turns the whole host's `docker` key into `null` (constraint 4). The other
  4 are in the image inspect response, where the failed lookup was shipped
  as empty tags for that image.
- It sends unversioned request paths: it joins an absolute path over its
  `/v1.xx` prefix, which drops the prefix.

**Why synchronous.**
- The collectors' work is blocking syscalls on /proc and /sys. Async has
  nothing to offer there: tokio would move them to `spawn_blocking`, which is
  the same thread.
- `run_privileged` must be able to abandon a subprocess that may never
  return, and only an OS thread can be abandoned safely.
- The collection loop is sequential by design under `WatchdogSec=90`.
- The Rust prototype ran on 3 long-lived threads, plus one short-lived
  worker per collector call; the Go prototype used 14 to 19 on the same
  16-core host.

**Consequences.**
- The release profile states `panic = "unwind"` explicitly and never uses
  `"abort"` (the prototype relied on the default). With it, a panic costs
  one collector a `null`; the prototype confirmed this when its own
  `tokio::time::timeout`, built outside the runtime, panicked.
- requests reads its environment on every call: a proxy per scheme
  (`HTTPS_PROXY` for https, `HTTP_PROXY` for http, `ALL_PROXY` last)
  honoring `NO_PROXY`, a CA bundle from `REQUESTS_CA_BUNDLE` or
  `CURL_CA_BUNDLE`, and `~/.netrc` credentials when no auth is set. Every
  HTTP collector (nginx, apache, caddy, haproxy, php-fpm, rabbitmq, tsdb,
  vllm, sglang, proxmox, and docker over `tcp://`, whose client is a
  requests session) relies on it. ureq 3 reads proxy variables too, but
  differently: its default configuration takes one proxy for every scheme,
  `ALL_PROXY` first, and it ignores the CA bundle and netrc variables. So:
  - the API and `ip.fivenines.io` clients set no proxy (`proxy(None)`):
    Python never proxies them (they connect through their own resolver),
    and a proxy in the service environment or in `.env` must not start
    carrying `/collect` after migration;
  - the HTTP collectors reproduce requests' per-scheme order, CA bundle
    and netrc handling, and the harness runs one input where
    `ALL_PROXY`, `HTTP_PROXY` and `HTTPS_PROXY` all differ;
  - rustls has no TLS 1.2 DHE or CBC suites, which Python's OpenSSL still
    offers: an endpoint that offers only those works today and would fail
    in Rust. The HTTP steps check for it or document the change.
- **Mutex poisoning.** A collector that panics while holding shared state
  poisons the lock, and every later `.lock().unwrap()` panics too. The
  prototype's `processes` and `cpu` state take their lock that way, so one
  panic there would become a `null` on every tick until the agent restarts
  (its `docker` state already recovers the guard). So shared state must
  either recover the guard (`PoisonError::into_inner`) and reset what it
  protects, or use a lock that cannot be poisoned. The workspace step
  enforces it with clippy `disallowed-methods` entries on every std call
  that reports poisoning (`Mutex::lock` and `try_lock`, `RwLock::read`,
  `write` and their `try_` forms, the `Condvar::wait` family), so locking
  goes through a wrapper that recovers. A `LazyLock` initializer stays
  infallible: a panic there poisons it for good (a `OnceLock` retries
  instead), so fallible reads belong in the collector call.
- An abandoned worker can still hold shared state. Single-flight per name
  protects the next tick only if every path into that state goes through the
  same name.
- Every counter is `u64`. Python integers are unbounded, and `usize`
  truncates on the 32-bit targets (armv7, i686). Values above 2^53 (qemu's
  `vm_cpu_time_nanoseconds_total`, docker's `cpu_throttling.throttled_time`,
  network and disk byte counters) stay integers in the JSON, and SNMP
  Counter64 values use the whole unsigned range, so `i64` is not enough
  either.
- Where Python sums counters with unbounded integers (docker's block I/O
  across devices, qemu's per-vCPU times, openvpn's bytes across sessions of
  one common name, and psutil's `nowrap`, below, which adds a wrapped
  counter's old value to the new one), the Rust sum is a `u128`, so the
  payload matches even above `u64::MAX`. It is serialized through typed
  `Serialize` structs or serde_json's `arbitrary_precision` feature, since
  serde_json's `Value` refuses a `u128` above `u64::MAX`. The release profile
  also states `overflow-checks = true` next to `panic = "unwind"`: an
  overflow nobody planned for costs a `null`, never a silently wrapped
  counter.
- psutil's `nowrap`, on by default in the `disk_io_counters` and
  `net_io_counters` calls the agent makes, adds a counter that wrapped back
  across reads; it is part of the psutil 7.2.1 behavior to reproduce. No
  live run reaches these boundaries, so the fixtures and harness inputs
  carry values above 2^32 and 2^53, `u64::MAX`, and a two-read sequence in
  which a counter wraps, and they run on the armv7 and i686 artifacts too.
- The armv7 and i686 glibc builds use the 64-bit file interfaces
  (`statvfs64` and the like, or the libc crate's 64-bit file-offset mode).
  With the 32-bit ones, `statvfs` fails with EOVERFLOW on a filesystem over
  2^32 blocks (16 TiB at 4 KiB), which Python's large-file build reads fine.
  musl is 64-bit there already.

## 6. libvirt

**Facts.**
- `qemu.py` opens and closes its connection on every tick, and makes 15
  distinct read-only calls that reach the daemon (plus a few, such as a
  domain's name and UUID, that the client answers locally):
  - connection: open read-only, version and type (every tick; the result is
    only logged), node info, list all domains, close;
  - per domain: state;
  - per running domain: max vCPUs; CPU time through a fallback chain (CPU
    stats per host CPU, then vCPU info, then total CPU stats, then
    `info()`); memory stats; XML description; then block stats per disk
    (`blockStatsFlags` first) and interface stats per interface.
- The URI allowlist already limits it to local unix sockets:
  `qemu:///system` and `qemu:///session`, over the `qemu` or `qemu+unix`
  scheme, with an optional `socket=` confined to a libvirt run directory
  and `mode=auto|direct|legacy`.
- The glibc build bundles libvirt 6.10.0 and libtirpc 1.3.3, built from
  source with the hypervisor drivers disabled. `libvirt.so.0` brings its
  own dependencies into the v1.20.1 bundle: libxml2, gnutls (with nettle,
  gmp, libtasn1 and p11-kit), glib, libnl, yajl and libselinux, whose clash
  with the host's sudo is why `get_clean_env` exists. The Alpine build
  bundles the libvirt of its Alpine 3.21 builder image. Windows and Synology
  exclude libvirt, so qemu never runs there.
- Since v1.20.4 (#171, #215) the whole collection runs on a single-flight
  `call_bounded` worker: the tick stops waiting after 15s, a 10s budget is
  checked before every call on a domain, a collection that ran out of time
  is retried after 60s then 120s, and a listed VM that cannot be read, or a
  connection lost mid-walk, makes the collection `null`, never a partial VM
  list. The libvirt calls themselves still block with no timeout: only the
  worker around them is abandoned. No event loop is registered, so
  libvirt's keepalive is off.
- The VM uptime no longer comes from libvirt: it is the age of the QEMU
  process found in `/proc` by its `-uuid` argument.
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
  - bundling libvirt and the libraries listed above;
  - `LD_LIBRARY_PATH` in child processes;
  - libvirt's own threads.
- The allowlist becomes structural: the client has no TLS, SSH or `ext`
  transport to refuse, reads no `libvirt.conf` and cannot autostart a daemon.
  No environment variable needs setting, and there is no parse to keep in step
  with libvirt's. The confinement of `socket=` to the libvirt run
  directories is not C-client fencing, though: it keeps a server-pushed URI
  from pointing the agent at any other local socket (#142), so the Rust
  client keeps it, in step with the server-side allowlist.
- Every read gets a socket timeout; today's calls have none, so a stuck one
  costs an abandoned thread.
- Loading the host's `libvirt.so.0` with `dlopen` would remove the bundling,
  but only on glibc, and it would keep every C-client behavior listed above.
- The remote protocol is also how today's bundled 6.10 client talks to
  current daemons.

**Consequences.** The qemu step owns:
- XDR encoding for about 15 procedures;
- the read-only connect and authentication handshake: none, or polkit on the
  read-only socket;
- the same accepted URI set as the Python allowlist (both schemes, both
  paths, `socket=` and `mode=`), everything else refused and reported as
  `null`;
- the v1.20.4 contract: the timeout, the per-domain budget, the backoff,
  and `null` rather than a partial VM list; and the uptime read from a
  `/proc` scan, so the test inputs include a fake `/proc` with QEMU
  processes next to the RPC server below;
- libvirt's socket selection with `mode=auto|direct|legacy`: for
  `qemu:///system`, the monolithic `libvirt-sock-ro` versus the modular
  `virtqemud-sock-ro` under the libvirt run directory; for
  `qemu:///session`, which has no read-only socket, `libvirt-sock` versus
  `virtqemud-sock` under `$XDG_RUNTIME_DIR/libvirt`, opened with the
  read-only connect flag. This selection is parity-critical and is tested
  against both daemon layouts, system and session;
- a test input both clients can talk to: a scripted libvirt RPC server on a
  unix socket, serving both socket layouts, with failure modes (a stuck
  call, a failed domain listing). Today's tests mock the Python binding,
  which the Rust client, speaking XDR, cannot consume.

qemu has no contract fixture yet, so its step first writes one from the
Python agent talking to that server, after the Python fixes listed in
section 9.

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
  first cannot bake Unix assumptions into the runtime. The check runs on a
  `windows-latest` runner, as `windows.yml` already does: ring and aws-lc-rs
  compile C for the target, which a Linux runner cannot do without an
  MSVC-compatible toolchain.

**Why.** Windows shares the runtime but almost none of the collection code or
the packaging. Its collector set is small enough to port in one step once the
runtime is proven on Linux.

The Windows step decides whether the binary integrates with the Service
Control Manager itself, which would remove WinSW and its .NET 4 dependency.

## 8. Python and Rust side by side

**Facts.** The agent never updates itself. Updates happen only when someone
runs them:
- Linux: the operator runs the update scripts.
- Windows: `fivenines_update.ps1` downloads and runs the latest MSI.
- Synology: the SPK is installed by hand.
- UNRAID: the binary already on flash is relaunched.

So an installed Python agent keeps running until its operator acts, whatever
this record decides.

**Decision.**
- **Before a platform's Rust GA.** Python is the shipping agent there and
  still gets features. A new collector lands in Python first, with its
  contract fixture, and that collector's Rust step reproduces the fixture.
  A collector with no fixture gets one first, written from the Python
  agent's output: 21 exist today, and cpu, memory, processes, systemd and
  snmp, among others, have none. Each step also covers the collector's
  `null`, empty and absent-key branches with failure inputs (a mock service,
  a recorded `/proc` fault) that the harness runs against both agents.
  Once a collector's Rust step has closed, any PR that changes its payload in
  Python must change the Rust side in the same PR. The differential harness
  fails otherwise (section 1), so CI enforces this, not process, for every
  path its recorded inputs reach; a PR that changes a closed collector's
  Python therefore also adds or changes a harness input for it (a CI path
  rule the harness step sets up).
- **At GA, per platform.**
  - Installers and update scripts install the Rust agent.
  - The update script migrates a Python install in place; the state files are
    compatible (Phase 3), `<config_dir>/.env` included: it can set
    `API_URL` and every variable a library or child reads.
  - The first Rust GA is the next major version (2.0.0) on the same version
    line. Nothing agent-side depends on a 1.x prefix: the installers compare
    no versions, and the MSI's major upgrade only needs a higher version.
    Version checks on the server side are outside this repository; the GA
    step (#210) reviews them.
  - One tag still builds every platform, so after the first GA a 2.x
    release carries Rust where it has shipped and Python elsewhere, and the
    version no longer says which agent runs. The payload's static data
    therefore names its implementation (`python` or `rust`).
    `pyproject.toml` and `rust/Cargo.toml` carry the same version on main,
    and the release job checks the tag against both.
- **After GA.**
  - The Python agent for that platform stays in maintenance for 12 months:
    security fixes and fixes that keep its payload valid, no new collectors.
  - Maintenance releases come from a maintenance branch cut at GA from the
    last commit that shipped that platform's Python agent. Its tags take
    the next patch versions of that release line (1.x.y after the Linux
    GA) and build only that platform's Python artifacts. Every platform
    GA bumps at least the minor version on main, so a later GA's
    maintenance patches (say 2.3.5 after a Windows GA in 2.4.0) never
    collide with main's tags either.
  - They go through the same signed pipeline but never become `latest`:
    not on GitHub, not in R2's `latest/`, which every installer reads. A
    maintenance release published as `latest` would downgrade every Rust
    host that next runs an installer. The release job's main-ancestry check
    accepts a maintenance branch for its own tags only.
  - The installers and update scripts gain a pinned-version mode that
    downloads a given release and verifies it, startup definitions
    included, against that release's own signed `SHA256SUMS`. It is how an
    operator stays on Python, and how a Rust host rolls back; the unverified
    `FIVENINES_AGENT_URL` path is not enough for either.
  - The Windows MSI accepts a downgrade and keeps the config directory and
    `TOKEN` across it. Today `MajorUpgrade` refuses any lower version, so
    a Rust host cannot go back in place. Whether an uninstall keeps the
    config directory is unverified: the MSI's `RemoveFolder` removes only
    an empty folder, and the `TOKEN` is written by a custom action. The
    Windows step tests both paths before the Windows GA: a downgrade in
    place, and an uninstall followed by a reinstall with the existing
    `TOKEN`.
  - The maintenance branch carries main's protection (required review,
    required checks including the harness, no direct pushes) before the
    release job's ancestry check accepts it, under one exact branch
    pattern: that check is the only review gate before signing.
  - It gets its own security coverage, since Dependabot, the weekly cold
    build and CodeQL only watch the default branch: scheduled jobs on main
    check the branch out for a cold build, CodeQL and a dependency audit
    (pip-audit), and certifi bumps stay a standing maintenance item.
  - Its last release stays downloadable, for rollback.
  - After that, its builds stop. The README states the date from GA onward.
  - Payloads are identical apart from the implementation name, so nothing
    needs retiring on the receiving side. An old Python agent keeps working
    after its end of support; it just stops getting fixes.

**Why 12 months.** Updates are started by operators, so the window exists for
them, not for us. It is the one number in this record that the Phase 4 beta's
version distribution should confirm or change before GA.

## 9. Python bugs found by the port are fixed in Python first

**Decision.** When the harness or a port shows that the Python agent is
wrong (rather than the port), the fix lands in Python first, with its test and
fixture. The Rust port then reproduces the fixed behavior. The harness keeps
no list of known differences, which gives "exact" a precise meaning:
- The comparison that gates runs both agents on recorded inputs: a fake
  `/proc` and `/sys` root, the mock services, scripted command output
  (behind a fake `sudo` that honors the pinned argv), shims for the values
  that come from syscalls rather than files (`statvfs`, `getifaddrs`, the
  ethtool ioctls, name-service lookups), and a clock the harness controls
  (below, left to the harness step). On those, the
  two payloads must be equal, and type-strictly: a boolean is not a number,
  an integer is not a float, and the key sets match.
- A comparison on a live host tolerates sampling drift (the prototype's
  `diff_payloads.py` tolerances) and never gates: two agents reading a live
  host at different instants never produce equal counters. Its comparator
  is never reused for the gate.
- Every payload string built from a Python exception, a `repr()`, a class
  name or captured log text is replaced in Python first by a stable reason
  code, and the fixtures are updated. As of v1.20.4 that covers
  `capability_reasons` (`pynvml not installed`); the error entries of
  openvpn, snmp, ceph, systemd, proxmox backups and the image inventory;
  `error_message` in rabbitmq, tsdb, vllm and sglang; `error_detail` in
  postgresql and mysql; mqtt's broker `error`; and `_telemetry[*].errors`.
  Each collector step checks its collector for sites added since.
  `uname.processor` is different: it is the output of `uname -p`, which
  CPython's `platform` module runs outside `get_clean_env` (`x86_64` on
  RHEL, empty on Debian), so the Rust agent runs the same command through
  its clean runner, or Python stops running it first (#184).
- Names that are not valid UTF-8 (a process name, a mount point, a device
  name: any local user can create one) keep Python's encoding. Python
  decodes them with `surrogateescape` and its JSON carries one lone
  `\udcXX` escape per invalid byte, which is one-to-one. The Rust agent
  keeps such names as bytes and writes the same escapes through its own
  serializer, since a Rust `String` cannot hold them. Any lossy decoding
  (U+FFFD) is ruled out: these names are keys (`partitions_usage` by mount
  point, `io` and `io_topology` by device, network rows by interface), and
  two names that differ only in invalid bytes would merge into one row.
  The recorded inputs include two such names that a lossy decoding would
  merge.
- Only three fields are excluded, by name: the implementation name
  (section 8), and `running_time` and `_telemetry[*].duration_ms`, which
  measure the agent, not the host. `version` is compared: both agents are
  built from the same commit and carry the same version, so a difference
  is a bug.

**Why.** A list of known differences is where real divergences hide. And the
fix reaches today's hosts months before the Rust agent does.

Found while preparing this record (status as of v1.20.4):
- `vm_vm_uptime_seconds_total` is always 0. `_get_vm_uptime` reads
  `dom.info()[5]` only when `info()` has six fields, and `virDomainGetInfo`
  returns five. Fixed in v1.20.4 (#215): the uptime is now the age of the
  QEMU process found by its `-uuid` argument.
- `vm_vcpu_time_nanoseconds_total` labels host CPUs as vCPUs on cgroup v1
  hosts: `getCPUStats(False)` returns one entry per host CPU, not per vCPU,
  and each is shipped with `vcpu` set to its index. On cgroup v2 that call
  fails and the `vcpus()` fallback reports real vCPUs (issue to be filed).
- The qemu collector's libvirt calls have no timeout, so one VM with a stuck
  QEMU monitor can stall the tick past `WatchdogSec` (fixed in v1.20.4,
  #171).
- The root installers map every unknown architecture to amd64 (section 2;
  fixed in v1.20.2, #170).
- The Windows binary ships without pynvml, so Windows hosts report no
  NVIDIA GPU metrics (section 2, issue to be filed).
- The synchronizer thread dies on a `/collect` answer without a `config`
  key: `send_metrics` reads `response["config"]` outside any `try`, and
  `run()` catches nothing. The main loop keeps feeding the watchdog, so the
  host stops reporting and systemd never restarts it (issue to be filed).
- Child processes inherited the host locale, and only `dpkg-query` and
  `rpm` forced `C`: smartctl formats `User Capacity`, which is shipped
  verbatim as `total_capacity`, with the locale's thousands separator.
  Fixed in v1.20.3 (#172): `get_clean_env` now sets `LC_ALL=C` and drops
  `LANGUAGE` for every child, and the Rust command runner does the same.

## Left to later steps

- Crate layout, lint set, coverage tool and threshold, the cargo-deny and
  cargo-audit policy, and whether to adopt cargo-vet: the workspace and CI
  step (#175). It also checks that `rust/rust-toolchain.toml` and the
  workspace `rust-version` agree: edition 2024's resolver prefers
  dependency versions compatible with `rust-version`, and compiling with
  the pinned toolchain is what enforces it.
- The DNS client for the API host and `ip.fivenines.io`: the synchronizer
  step. It must match how the agent uses dnspython 2.8 today:
  - common to both names: one resolver per process, built once from
    `/etc/resolv.conf` (from the registry on Windows, which the Windows step
    reconciles); `/etc/hosts` never read; every name queried as absolute,
    with no search list and `ndots` ignored (dnspython's
    `use_search_by_default` is off); the TTL cache flushed on any
    resolution failure, not on a connect or TLS failure;
  - the API host: A first, and AAAA only when the A lookup fails or its
    first address fails to connect or complete TLS; only the first address
    of an answer tried;
  - `ip.fivenines.io`: one family per lookup (A for the IPv4 address, AAAA
    for the IPv6 one), every address of the answer tried in order.
- The PostgreSQL and MQTT clients: their steps, within section 5.
- How the Windows service is run: the Windows step.
- The RSS soak test used as a gate in sections 3 and 4: the release
  pipeline step (#177). It runs a fixed profile that includes the Docker
  mock, long enough to see slow growth (the glibc build still crept after 5
  minutes), and fails on the slope of `Private_Dirty` rather than on an
  absolute RSS. It also says how armv7 is measured, since QEMU user
  emulation adds its own memory to the process. It must run on a pull
  request too, path-filtered on `rust/rust-toolchain.toml`, the zig or
  sysroot pin, `rust/Cargo.lock`, the source that sets the arena cap and
  the builder Dockerfiles, since section 4 makes it a gate on every
  toolchain change and `build-release.yml` has no `pull_request` trigger.
- The release pipeline step (#177) also settles the armv7 glibc floor and
  how it is built, the cross toolchain for armv7 (zig or a sysroot) and its
  pin, and the `M_ARENA_MAX` value. It verifies every toolchain download
  the way every other build download is verified today: rustup-init, the
  toolchains, the zig or sysroot tarball and every cargo subcommand against
  digests committed in the repository (`cargo install --locked` at pinned
  versions), with no `curl | sh`.
- The harness step (#176) settles how the recorded inputs of section 9
  reach both agents: a mount namespace with bind-mounted `/proc` and `/sys`
  trees, for example, and a clock source that also works for a static
  binary, which `LD_PRELOAD` tools such as libfaketime cannot reach. It
  also names the Python each platform is compared against: the source
  tree, or the frozen artifact that hosts actually run (the Alpine binary
  lacks pynvml, for example); comparing against the artifacts adds
  `Dockerfile*`, `py2exe*.sh` and `ci/requirements/` to the trigger paths
  of section 1. And it says what the armv7 and i686 Rust agents are
  compared against, since no Python build exists there (the Python agent
  run from source in the same emulated container, or recorded fixtures
  only); `uname` and the CPU model then follow the emulated target. The
  same step also settles:
  - the clock: stepped between ticks by the same amount for both agents,
    so the time-driven branches (qemu's budget and backoff, snmp's
    interval replay, the docker, openvpn and ping deadlines) are reachable.
    Which clocks it controls decides whether the ages read from the
    monotonic clock (mqtt's, proxmox's `age_s`) and the ping latencies
    (Python times them with the wall clock) are compared or join the
    exclusions of section 9;
  - the scope before GA: the mock config enables only the collectors whose
    step has closed, and capabilities are compared only for their probes.
    That list only grows, and goes at GA;
  - the scope after each GA: collectors that only platforms past GA run are
    compared against their fixtures or the maintenance branch's Python, not
    main's, and the maintenance branch's own harness compares Python
    against its fixtures;
  - the Windows `cargo check` of section 7 runs on pull requests and is a
    required check, like the harness.
- The collection loop step (#180) settles:
  - a panic policy for the long-lived threads (synchronizer, uploaders,
    MQTT), which `call_bounded` does not cover: catch the panic, log it and
    resume, or abort so `Restart=always` recovers; the watchdog is fed only
    while the synchronizer is alive (section 9 lists the Python bug); and
    threads start through `thread::Builder::spawn`, with a failed spawn
    mapped to `null`, since `thread::spawn` panics under a pids limit;
  - the order under the tick budget: a fixed order would starve the same
    tail (ping, snmp, mqtt) on every tick, so the start rotates or the tail
    keeps a reserve; mqtt's reconcile always runs, and a skipped mqtt ships
    its error envelope, never a missing key; snmp keeps its in-flight
    accounting. More generally, each collector's skip value follows its
    contract: tsdb, vllm, sglang and rabbitmq never ship `null` (their
    `reachable: false` envelope), so a deadline or a skip ships that
    envelope instead;
  - whether the interval cap of section 5 stays once the sleep feeds the
    watchdog, since a cap rewrites a valid server interval such as 300s.
- The beta and GA steps (#209, #210): one pre-release spelling for both
  manifests (PEP 440 writes `2.0.0b1`, SemVer `2.0.0-beta.1`, and the MSI
  takes no suffix), and the limits of pinned mode: it starts at v1.18.1,
  the first release that publishes the startup definitions, and a signing
  key rotation keeps the previous key for verifying older releases.
- The system core step (#184) checks the libc-dependent sources: under
  musl, `os.getloadavg` and `os.cpu_count` come from `sysinfo` and
  `sched_getaffinity` rather than `/proc/loadavg` and `/sys`, so the Alpine
  Python may ship unrounded load averages and the affinity CPU count. The
  step matches each Python build per libc, or normalizes Python first.

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
- Rust target tiers and floors (i686 tier 1 with SSE2, aarch64 kernel 4.1):
  https://doc.rust-lang.org/rustc/platform-support.html
- 32-bit Raspberry Pi OS ships a 64-bit kernel with a 32-bit userland:
  https://www.raspberrypi.com/news/bookworm-the-new-version-of-raspberry-pi-os/
