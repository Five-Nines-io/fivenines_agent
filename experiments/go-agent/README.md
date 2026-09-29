# Go prototype of the agent (experiment, not production code)

What a Go rewrite of fivenines-agent would buy, measured rather than guessed.
This is the collection loop, the synchronizer and 8 collectors (cpu, memory,
load_average, file handles, network, partitions, io, processes), producing the
same `/collect` payload as the Python agent for those keys. The other ~45
collectors, the permission probe, SIGHUP, log capture, image inventory, the
systemd watchdog and Windows specifics are not ported.

## Build

    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o go-agent .
    go test ./...          # contract_test.go: the null / [] / absent traps

No cgo: the same command cross-compiles for linux/{amd64,arm64,386,arm},
windows/amd64, darwin/arm64 and freebsd/amd64 from one machine.

## Reproduce the measurements

`../bench/` holds the harness, shared with `../rust-agent` (paths assume
`/tmp/fivenines-bench`, with the v1.20.1 release extracted there and the
binaries in `bin/`):

    ../bench/measure.sh LABEL PROFILE INTERVAL SECONDS -- AGENT_BINARY
    ../bench/diff_payloads.py PYTHON_PAYLOAD.json GO_PAYLOAD.json

`measure.sh` starts `mock.py` (a fake API that answers with a config and saves
every decompressed payload), runs the agent against it and samples
`/proc/<pid>` every second. PROFILE is `core`, `procs` (core + processes) or
`full` (the agent's own `_DRY_RUN_CONFIG`). CPU includes reaped children.

## Results (2026-09-29, 16-core Linux container, ~300 processes)

Python = the signed v1.20.1 release binary (PyInstaller), not a dev venv.

| profile, interval        | Python RSS | Go RSS  | Python CPU/tick | Go CPU/tick |
|--------------------------|-----------:|--------:|----------------:|------------:|
| core, 5s                 | 44.7 MB    | 12.8 MB | ~3.5 ms         | ~2.7 ms     |
| core, 1s                 | 44.5 MB    | 13.2 MB | ~3.8 ms         | ~4.1 ms     |
| core + processes, 1s     | 46.3 MB    | 15.1 MB | ~57 ms          | ~32 ms      |
| full (Python only), 5s   | 46.1 MB    | -       | ~50-85 ms       | -           |

Startup CPU: 0.17-0.30 s (Python) vs 0.00-0.03 s (Go).
Artifact: 50 MB on disk / 22 MB tar.gz (Python, every collector) vs
6.9 MB / 2.9 MB gzip (Go, these 8 collectors only).

## What the payload diff caught

Every one of these produced a well-formed payload with no error:

- `disk.Partitions(false)` (gopsutil) drops bind mounts. In a container every
  real mount is a bind, so `partitions_metadata` was `[]` and the disks
  silently left monitoring. psutil keeps them.
- `disk.IOCounters()` (gopsutil) drops devices whose counters are all zero:
  7 idle loop devices missing from `io`.
- `uname.processor` is `uname -p` in Python ("unknown" -> "" on Debian/Ubuntu,
  the architecture on RHEL), not the machine name.

Found by reading psutil instead: memory `percent` is (total - available) /
total, not gopsutil's UsedPercent; `cpu_usage` and `cpu_times` are positional
arrays (namedtuples); a 15-byte process name is completed from argv[0];
`cpu_percent` is a delta against the previous tick keyed on (pid, start
time); `nowrap=True` keeps disk/net counters monotonic (NOT reproduced).

Known divergences the diff could not see on this host (every interface was
running, every user in /etc/passwd):

- psutil's `isup` is IFF_RUNNING (the link), not IFF_UP (the admin state);
  this prototype checks "up", so an admin-up interface with no carrier is
  reported here and not by Python. The Rust prototype follows psutil.
- psutil splits a rewritten cmdline (setproctitle) on spaces before taking
  argv[0]; this prototype only splits on NUL.
- A CGO_ENABLED=0 binary resolves user names from /etc/passwd only (no NSS):
  LDAP/SSSD users and systemd DynamicUser services would show as uids.

## Docker collector (docker.go)

Ported with the official client (github.com/moby/moby/client v0.6.0): the
binary grows 7.2 -> 7.9 MB and the dependency graph 30 -> 57 modules, 24 of the
new packages OpenTelemetry. Stats are decoded untyped with json.Number, since
pids_stats / throttling_data / networks are passed through verbatim and
system_cpu_usage (~4e16 on a 30-day 16-core host) is past float64's 2**53.

The first version classified a daemon error on ONE container (a 500) as "skip
it", which ships a partial map the server prunes. docker.py sends null there:
docker-py's APIError subclasses requests' RequestException, so it lands in the
transport branch. The payload diff could not see it (the mock never errored);
the mock's error500 fault mode did. Only 404 is skipped now.

Runtime tuning, core + processes (all side by side):

| env                                   | RSS     | CPU/tick | threads |
|---------------------------------------|--------:|---------:|--------:|
| default                               | 13.6 MB | ~11 ms   | 14      |
| GOMAXPROCS=1                          | 12.3 MB | ~10 ms   | 7       |
| GOGC=25                               | 11.2 MB | ~16 ms   | 15      |
| GOMEMLIMIT=4MiB                       | 11.2 MB | ~98 ms   | 16      |
| GOMAXPROCS=1 GOGC=25 GOMEMLIMIT=4MiB  | 8.6 MB  | ~18 ms   | 6       |
