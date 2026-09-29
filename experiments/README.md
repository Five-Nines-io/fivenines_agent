# Rewrite experiments

Two prototypes of the agent's collection loop and 9 collectors (cpu, memory,
load_average, file handles, network, partitions, io, processes, docker),
producing the same `/collect` payload as the Python agent, measured side by
side against the signed v1.20.1 release binary:

- `go-agent/`   -- Go; docker through the official moby client
- `rust-agent/` -- Rust; docker through bollard on a current-thread tokio runtime
- `bench/`      -- mock API, mock Docker daemon (with fault modes), /proc
                   sampler, payload differ, musl allocator repro, and the
                   drivers that produced the tables below (run-all.sh,
                   run-gotune.sh, run-docker.sh, test-faults.sh; they assume
                   the v1.20.1 release and the built binaries under
                   /tmp/fivenines-bench)

## Footprint (1s interval, 90 ticks, all four side by side)

| core + processes + docker (40 containers) | RSS     | CPU/tick | threads | binary x86_64 |
|-------------------------------------------|--------:|---------:|--------:|--------------:|
| Python (release)                          | 47.4 MB | ~145 ms  | 4       | 50 MB dir     |
| Go                                        | 16.3 MB | ~64 ms   | 19      | 7.9 MB static |
| Rust (glibc)                              | 7.7 MB  | ~36 ms   | 3       | 3.7 MB        |
| Rust (musl)                               | 4.0 MB  | ~43 ms   | 3       | 3.7 MB static |

Without docker the same agents were 46.3 / 13.7 / 5.1 / 2.2 MB: the docker
client costs Go +2.6 MB, Rust +1.8 to +2.6 MB. The Python agent imports every
collector's library at startup, so its figure already includes them all; the
prototypes carry 9 of ~50 collectors, and every SDK added narrows the ratio.
At the real 60s interval every CPU figure is below 0.3%.

Go runtime tuning (core + processes): GOMAXPROCS=1 GOGC=25 GOMEMLIMIT=4MiB
brings Go from 13.6 to 8.6 MB for +60% CPU; GOMEMLIMIT alone below the live
heap costs 8x CPU (GC thrash). Rust musl stays ~4x smaller than tuned Go.

## Contract checks (bench/mock_docker.py fault modes, docker key)

| mode                          | Python        | Go            | Rust (bollard) |
|-------------------------------|---------------|---------------|----------------|
| normal                        | 40 containers | 40            | 40             |
| one container 404 (vanished)  | 39 (skipped)  | 39            | 39             |
| one container 500 on stats    | null          | null          | null           |
| unknown container state       | passed through| passed through| null           |
| old daemon (API 1.41)         | 40            | 40            | 40             |

Not production code. Nothing here is wired into the build, CI or packaging.
