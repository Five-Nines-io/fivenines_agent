# Rust prototype of the agent (experiment, not production code)

The sibling of `../go-agent`: same scope (collection loop, synchronizer, and the
cpu, memory, load_average, file handles, network, partitions, io and processes
collectors), same `/collect` payload, measured with the same harness
(`../bench`). Collectors read /proc and /sys directly, the way psutil does,
rather than through `sysinfo`: the Go prototype showed that the nearest library
function is not psutil's semantics.

## Build

    cargo build --release          # glibc, dynamically linked, 2.4 MB
    cargo test                     # contract.rs (tri-state), bounded.rs

Static musl: `ring` (rustls' crypto, C + asm) needs a C compiler for the
target. On x86_64 the host gcc works:

    CC_x86_64_unknown_linux_musl=gcc cargo build --release --target x86_64-unknown-linux-musl

Cross-compiling (aarch64, armv7, i686 musl) goes through cargo-zigbuild, and
the zig version MUST be pinned: with zig 0.16.0 the linked libc frees nothing
(`../bench/musl_alloc_repro.rs`: 716 MB after 600 simulated ticks, 0.4 MB with
zig 0.14.1 or Rust's own musl). The agent built that way grew ~0.09 MB/tick.

    cargo zigbuild --release --target aarch64-unknown-linux-musl   # zig 0.14.1

Windows does not compile (10 errors): nix, std::os::unix and signal-hook's
iterator are Unix-only. A Windows agent would be separate cfg-gated modules --
where Go compiled for Windows and would have failed at run time instead.

## Results (2026-09-29, same host and harness as ../go-agent)

All four agents ran side by side, 1s interval, 90 ticks.

| profile          | Python RSS | Go RSS  | Rust glibc RSS | Rust musl RSS |
|------------------|-----------:|--------:|---------------:|--------------:|
| core             | 44.4 MB    | 12.9 MB | 4.2 MB         | 2.1 MB        |
| core + processes | 46.3 MB    | 13.7 MB | 5.1 MB         | 2.2 MB        |

| CPU per tick     | Python | Go    | Rust glibc | Rust musl |
|------------------|-------:|------:|-----------:|----------:|
| core             | ~4 ms  | ~4 ms | ~3 ms      | ~4 ms     |
| core + processes | ~42 ms | ~23 ms| ~17 ms     | ~19 ms    |

Threads: Python 4, Go 15-16 (runtime), Rust 3.
Binary: 2.4 MB (x86_64 musl), 2.0 MB (aarch64), 1.9 MB (armv7); ~1.1 MB gzip.
Build: cold debug 10 s, cold release (LTO) 33 s, release rebuild after a
one-file edit 15 s (Go: cold 8 s, rebuild 0.6 s).

## What the payload diff caught

- `memory.used` was 1.8 GB off. psutil 6 changed it to total - available; this
  port first shipped the older total - free - cached - buffers. A port freezes
  one psutil version's semantics; the Python agent gets the next by bumping a
  pin.

After the fix, no divergence on the ported keys (processes: 278 common pids,
same pid/ppid/name/username/shape).

## Not verified here

- Static binaries resolve user names without NSS: Go (CGO_ENABLED=0) reads
  /etc/passwd only; musl reads /etc/passwd and asks nscd if it runs. LDAP/SSSD
  users and systemd DynamicUser services would show as uids where Python (glibc
  NSS) shows names. The glibc Rust build keeps NSS.
- psutil's nowrap (monotonic counters across a wrap) is not reproduced, and
  `available` on kernels without MemAvailable is a stand-in for psutil's
  /proc/zoneinfo estimate.

## Docker collector (docker.rs)

bollard 0.21 (hyper + tokio) on a current-thread runtime built once: no extra
threads (3 in total). Binary 2.4 -> 3.7 MB, 106 crates.

- bollard's models are closed enums: a container state the stubs do not know
  (mock fault `newstate`) fails the whole list deserialization, so docker is
  null on that host for as long as the container exists. Python and Go pass
  the string through. Fixing it means forking bollard-stubs or talking to the
  socket without bollard's models.
- bollard builds `/v1.53/...` and then `Url::join`s the absolute path over it,
  which drops the version prefix: every request is unversioned and the daemon
  answers in its own API version. It works against an API 1.41 daemon, by
  accident rather than by negotiation.
- `tokio::time::timeout(...)` evaluated as `block_on`'s argument panics ("no
  reactor running"). call_bounded contained it: docker was null, the agent
  kept running -- the reason panic = "unwind" stays.
