# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

fivenines-agent is a monitoring agent that collects server metrics and sends them to the fivenines API (https://fivenines.io). The agent runs continuously, probing system capabilities and collecting various metrics at configurable intervals.

## Development Commands

### Setup
```bash
# Install dependencies using Poetry
make install
```

### Code Quality
```bash
# Run linters (isort, black, flake8, mypy, bandit)
make lint

# Auto-format code (isort, black)
make format

# Run tests with coverage (requires 100% coverage)
make test

# Run a single test file
poetry run pytest tests/test_collectors.py -v
```

### Build Binary
```bash
# Build standalone executable for Linux (uses PyInstaller)
./py2exe.sh
```

The build process creates a self-contained binary at `./dist/linux/fivenines-agent-linux-*/` that includes all dependencies (libvirt, libcrypt, etc.) for compatibility with CentOS 7+.

### Running the Agent
```bash
# Run directly with Poetry
poetry run fivenines_agent

# Run with dry-run mode (collects metrics once and exits, prints JSON to stdout)
poetry run fivenines_agent --dry-run

# Check version
poetry run fivenines_agent --version
```

## Architecture

### Core Components

**Agent Loop (`agent.py`)**
- Main orchestrator that runs the collection loop
- Handles signals (SIGTERM, SIGINT for shutdown; SIGHUP for capability refresh)
- Collects static info once (version, uname, boot time, capabilities, user context)
- On each iteration: collects configured metrics, serializes + gzips the payload (`serialize_payload`) and enqueues the compressed blob, sleeps until next interval; a payload that fails JSON serialization drops that tick with an error instead of crashing the agent, and the full-payload debug dump is gated on `debug_enabled()`
- Bounds the server-pushed `ping` map before its sequential loop (hostile or fat-fingered config must not stretch a tick past `WatchdogSec=90`): at most `MAX_PING_TARGETS` (10) targets per tick, picked through a rotating start offset so an over-cap map still cycles through every target across ticks; region/host strings over `MAX_PING_FIELD_CHARS` (200) are dropped; and the whole loop runs under a `PING_LOOP_DEADLINE` (30s) wall-clock budget, because `tcp_ping`'s 5s timeout does not cover DNS resolution, so the count cap alone is not enough
- Manages graceful shutdown with proper cleanup

**Permission Probing (`permissions.py`)**
- Detects available monitoring capabilities at startup based on file permissions, sudo access, and group memberships
- Re-probes automatically every 5 minutes or on SIGHUP signal to detect permission changes; between full probes, a capability that is enabled in config but keeps probing False is re-probed with exponential backoff (60s base, 120s cap) instead of every tick, so a permanently-missing permission stops costing a subprocess spawn per tick while a just-granted one still appears within ~2 minutes (SIGHUP forces an immediate full probe)
- Capabilities include: core metrics (always available), hardware sensors, storage (SMART/RAID), services (Docker/QEMU/Proxmox/systemd), kernel surfaces (cgroup, tri-state "v1"/"v2"/None), security (fail2ban), VPN (`wireguard`, probed via the EXACT `sudo -n wg show all dump` argv the collector runs -- probing anything shorter would report available where the real dump is denied), logs (`journald` read access, probed via `journalctl -n 0`), etc.
- A capability normally GATES its collector (`collectors._is_capability_gated`: present-and-False -> the key is omitted from the payload). `collectors.CAPABILITY_GATE_EXEMPT` opts a key out of that, for collectors whose contract is "a privilege failure is a null, not a missing key" -- today only `wireguard`. For those, the capability is informational: banner + `pending_capabilities` + reason, nothing else
- Prints a capabilities banner showing what features are available/unavailable with hints

**Synchronizer (`synchronizer.py`)**
- Background thread that sends collected data to the fivenines API
- Fetches configuration from server before starting metric collection
- Handles retries with linear backoff (`retry_interval * try_count`)
- Metric payloads arrive pre-compressed from the agent loop (see SynchronizationQueue); dict payloads (config fetch, logs, image packages) are gzipped here at level 6 (`GZIP_LEVEL`)
- Uses custom DNS resolution with IPv4/IPv6 fallback, backed by a TTL-honoring in-memory DNS cache that is flushed on any resolution failure so a cached negative answer can never pin the agent offline
- Reuses one persistent HTTPS connection per thread (`auto_open=0`, so a server-side close can never bypass the custom resolver, the certifi trust root, or a custom port): a stale kept-alive socket is rebuilt once without consuming a retry, while an HTTP-status error keeps the healthy connection instead of reconnecting against an already-struggling API
- The token swap writes `TOKEN` owner-only (see Config-Dir State Files under Important Patterns): a reader with the per-host token can POST get_config and receive every service credential the config carries

**SynchronizationQueue (`synchronization_queue.py`)**
- Thread-safe queue with maxsize limit for buffering collected metrics, held as gzip blobs compressed at enqueue time so an API-outage backlog costs a few MB instead of hundreds of MB of raw payload dicts
- Prevents memory exhaustion if API is unreachable

**Log Uploader (`log_uploader.py`, `log_capture.py`)**
- Dedicated `LogUploader` worker thread + bounded queue that upload incident log-capture bundles to `/logs` via `Synchronizer.send_logs`, kept off the metric-collection loop so a slow/large upload never stalls collection, `/collect`, or the systemd watchdog
- `CaptureCoordinator` applies the backend `capture_logs` command with a capture_id nonce + on-disk `last_capture_id` persistence: each command fires exactly once and never replays after a `Restart=always` restart; `last_served` advances only after a confirmed upload, so a failed capture retries
- Part of log-monitoring V1; inert until the backend implements the `/collect` `capture_logs` command and the `/logs` endpoint

**Out-of-band Upload Workers (`queue_uploader.py`)**
- `QueueUploader` is the shared thread body for every off-loop uploader: bounded-queue drain, `None` shutdown sentinel, per-job isolation (a bad job never kills the thread), and exactly one `on_success`/`on_failure` callback per job so a coordinator can retire or retry the work item
- Subclasses supply only vocabulary (`label`, `job_id_key`, `payload_noun`). Users: `LogUploader` (`/logs`) and `ImageInventoryUploader` (`/image_packages`)
- Anything slower or larger than a metric payload belongs here rather than on the collection loop (which the systemd watchdog bounds) or the Synchronizer drain

**Image Inventory Worker (`docker_image_inventory.py`)**
- `ImageInventoryUploader` + `ImageInventoryCoordinator`: extraction (N archive fetches + tar parsing) and the `/image_packages` POST run entirely off the collection loop, so a 3-image tick does not extend the tick
- Image digests are immutable, so each is extracted **once per image forever**: done digests persist to `image_inventory_done` (bounded, FIFO-evicted) and survive a `Restart=always` restart. Failures back off exponentially and are given up on after `max_attempts` (in-memory, so a long outage cannot permanently blind an image); a queue-full shed releases the slot without counting an attempt
- `once per image forever` has one escape hatch, and it is server-driven: a transient `api_error` is reported INSIDE a 200, so the digest is marked done and the image would read "not scannable" forever. `ImageInventoryCoordinator.reset()` (via the top-level `rescan_images` config key) re-opens exactly those. A digest with no failure history is re-offered on the same tick the FIRST time it is requested; one the agent had already **given up** on is re-armed onto its retry ladder instead of made immediately eligible. Because the directive is level-triggered (the last `/collect` config is replayed by the Synchronizer during an outage, and a buggy server could re-send it), two agent-side floors keep a stale/looping request from re-extracting every tick: the retry ladder for given-up digests, and a per-digest `rescan_min_interval` (default 1h, `RESCAN_MIN_INTERVAL_SECONDS`) that throttles repeat re-opens even in the immediate `attempts==0` case. `apply_rescan_requests` bounds the untrusted list on three axes -- entries scanned (`MAX_RESCAN_SCANNED`), digests honoured (`MAX_RESCAN_IMAGES`), per-entry length (`MAX_FIELD_CHARS`) -- so a hostile config cannot burn the watchdog-bounded collection loop. `_persist` writes via a temp file + `os.replace` under a dedicated lock and re-reads the done set under `_lock`, since `reset()` (collection loop) is now a second writer alongside `mark_done()` (uploader thread)
- Inert until the backend sends the top-level `image_inventory` config key and implements `/image_packages`

**Subprocess Utilities (`subprocess_utils.py`)**
- Critical for PyInstaller compatibility: removes LD_LIBRARY_PATH and other environment variables that can interfere with system commands
- PyInstaller bundles libraries (like libselinux from libvirt) that conflict with system utilities (sudo, smartctl, mdadm)
- Always use `get_clean_env()` when calling subprocess commands

**Bounded HTTP Body Reads (`http_body.py`)**
- `read_capped_body(response, max_bytes, timeout_s)` is the one shared bounded read for HTTP collectors fetching server-pushed URLs: the caller issues `requests.get(..., stream=True, allow_redirects=False)` and the body is streamed under BOTH a byte cap (checked chunk-by-chunk, never buffer-then-check) and a wall-clock deadline -- `requests`' scalar `timeout` is a per-socket-op inactivity timeout, so a trickling endpoint never trips it and would otherwise stall the watchdog-bounded collection loop
- Raises `BodyOverBudget` (a ValueError) that each caller maps onto its existing failure contract; the response is closed on every path. Users: `tsdb.py` (8 MB / 15s), `php_fpm.py` (1 MB / 5s), `rabbitmq.py` (16 MB / 20s). `redis.py` applies the same cap+deadline posture to its raw-socket INFO read (1 MB / 5s)
- Any new collector reading a server-pushed HTTP URL must fetch through this posture (streamed, redirects refused, capped) instead of `response.text` / `response.json()`

**Environment (`env.py`)**
- Central source for runtime configuration: `api_url()`, `config_dir()`, `dry_run()`, `log_level()`
- Config directory defaults to `/etc/fivenines_agent`; override with `CONFIG_DIR` env var
- `get_user_context()` collects user/group info sent with each payload

**Collector Registry (`collectors.py`)**
- Declarative `COLLECTORS` list maps config keys to `(data_key, callable, pass_kwargs)` tuples
- `agent.py` iterates this registry each tick; `pass_kwargs=True` unpacks the config dict as `**kwargs` to the callable
- Add new metrics here rather than modifying the agent loop

### Metric Collectors

Each metric collector is a separate module that exports functions to collect specific metrics:

- **Core metrics** (always enabled): `cpu.py`, `memory.py`, `load_average.py`, `io.py`, `network.py` (per-interface byte/packet/error/drop counters, plus Linux bridge detection, `interface_type` bridge/physical/virtual, `network_link_speed_bps` from `/sys/class/net/<if>/speed`, and `bridge_member_count` so the backend can compute per-interface saturation), `partitions.py`, `files.py`, `ports.py`, `processes.py`, `temperatures.py`, `fans.py`
- **Hardware/GPU**: `gpu.py` (NVIDIA GPU metrics via `pynvml`, registered under the `nvidia_gpu` config key; the NVML session is initialized once per process and kept alive across ticks -- a session-level failure such as a driver reload tears it down so the next tick re-initializes cleanly)
- **Storage**: `smart_storage.py` (requires sudo smartctl), `raid_storage.py` (requires sudo mdadm), `zfs.py`
- **Services**: `docker.py` (per-container state + metrics: status/health/exit-code/OOM/restart-count for every container from its first tick, plus running-container CPU/memory/block-I/O; keyed by full container id; a per-thread cached Docker client (10s per-API-call timeout, `CLIENT_TIMEOUT`) plus a 25s wall-clock collection budget (`COLLECT_DEADLINE`) bound a wedged daemon under the systemd watchdog; `docker_metrics` returns `None` on daemon-unreachable, budget exhaustion, or a mid-pass transport error -- never a partial container map -- so the server never prunes on error, `{}` only when genuinely zero containers), `qemu.py` (libvirt read-only connection; the configured `uri` is checked against an agent-side allowlist BEFORE any libvirt call (agent #142): only `qemu:///system`, `qemu:///session` and `qemu+unix:///...` with no host component and at most `?socket=<file inside /run/libvirt/, /var/run/libvirt/ or $XDG_RUNTIME_DIR/libvirt/>` + `?mode=auto|direct|legacy` are opened (a `;` in the query is refused so the agent and libvirt never parse a query differently), because a libvirt URI also selects the TRANSPORT and `ext`/`ssh`/`libssh`/`tcp`/`tls` run a local command or dial out regardless of `openReadOnly()`. A refused URI logs its reason at error level once per CHANGE of refused URI and at debug while the same one repeats (the config is level-triggered and the collector is re-instantiated per tick; an accepted URI clears the register, so a re-introduced bad URI is an error again) -- the reason only, never the URI or any value from it; the scheme is echoed only when it is a libvirt spelling, since those lines reach the journal and the error telemetry, and URIs over `LIBVIRT_URI_MAX_CHARS` are refused before parsing. A refused URI never reaches libvirt and reports `None`. `None` is also reported on a failed connection or domain listing; `[]` means libvirt listed zero VMs (the docker "report everything or null" contract). `LIBVIRT_AUTOSTART=0` is set once at import unless the operator's environment already sets it, so `qemu:///session` never forks a session daemon from the agent. The permissions probe opens the same `DEFAULT_LIBVIRT_URI` constant, pinned against the allowlist in tests), `proxmox.py`, `caddy.py`, `nginx.py`, `apache.py` (Apache mod_status `?auto`: busy/idle workers, per-state scoreboard, request/byte throughput; MPM-tolerant key/value parse, `None` on failure), `haproxy.py` (HAProxy `show stat` over the AF_UNIX stats socket or HTTP `;csv` endpoint: per-frontend/backend/server rows with verbatim status and raw cumulative counters; CSV columns mapped by header name, `server` rows capped at 400 problems-first; `[]` when genuinely zero proxies, `None` on failure), `postgresql.py`, `mysql.py` (MySQL/MariaDB via the `mysql`/`mariadb` CLI; emits a reachable/unreachable/config-error status plus connections, query/InnoDB buffer-pool metrics, replication lag, and Galera/wsrep cluster state via a whitelisted `SHOW GLOBAL STATUS LIKE 'wsrep%'` -- implicit detection, keys absent on non-Galera hosts), `redis.py` (single `INFO` read over a raw socket; AUTH/INFO/QUIT are sent in RESP array framing -- length-prefixed bulk strings -- so a config-pushed password is pure data: a CRLF inside it cannot inject commands into the local Redis and a space no longer breaks AUTH, both of which the old inline framing allowed; the reply read is bounded by a 1 MB cap + 5s wall-clock deadline, same posture as `http_body.read_capped_body`), `memcached.py` (single `stats` command over TCP; flat whitelisted snapshot of version/uptime/connections/bytes-vs-limit plus RAW cumulative `*_total` counters (hits/misses/get/set/evictions/expired-unfetched); `None` on collection failure -- refused/timeout/no-`END`-terminator; config-driven `{host, port}`, no capability gate), `rabbitmq.py` (RabbitMQ management-API poll: a reachability envelope + node alarms/fd-socket headroom + a bounded per-queue array = top-N by `messages` UNION top-N by `messages_unacknowledged` UNION `include_queues`, with `queues_total` carrying the broker's true count. postgresql-style `reachable:false` envelope -- never `None` -- on a dead broker OR an untrustworthy/partial queue listing, so the server never prunes queue rows or false-resolves an open `rabbitmq_queue_backlog` incident; raw `message_stats` counters (server derives rates); include tail bounded by a count cap AND a wall-clock watchdog deadline. Responses are streamed with redirects refused and read via `http_body.read_capped_body` (16 MB cap, 20s body deadline), and error-path responses are closed so keep-alive sockets return to the pool. Config-driven `{url, username, password, vhost, include_queues}`, no capability gate), `systemd.py` (per-unit health + inventory delta-sync, requires systemctl; journalctl only for failure journal tails, redacted before send)
- **Security**: `fail2ban.py` (requires sudo fail2ban-client)
- **VPN**: `wireguard.py` (one `sudo -n wg show all dump` -> full current set of interfaces + peers. The privilege is command-scoped, NOT a process capability (#144): the packaged unit granted `AmbientCapabilities=CAP_NET_ADMIN` until 1.17.6, which every install got whether or not it monitored WireGuard and which, being ambient, was inherited across `execve` by every child the agent spawned; the documented sudoers rule pins the FULL argv (`fivenines ALL=(root) NOPASSWD: /usr/bin/wg show all dump`), so it grants the one read-only dump and denies `wg set`. A missing rule is a non-zero exit + stderr, i.e. already `None` under the rules below -- never an empty peer list. The alias read of `/etc/wireguard/<if>.conf` deliberately does NOT go through sudo; `None` on ANY ambiguous outcome -- missing `wg`, non-zero exit (which is also what a missing sudoers rule looks like), timeout, or **any stderr from `wg`**, because unprivileged `wg` can enumerate interface names but not read them and still exit 0 with a PARTIAL dump that the server would vanish-prune against. Lines sudo wrote about ITSELF are split off first (`_split_stderr`): sudo warns and still runs the command -- "sudo: unable to resolve host" fires on every call on a box whose hostname is not in /etc/hosts -- and folding that into the stderr rule would have turned working hosts permanently null the moment the read moved behind sudo, while anything sudo actually failed at is a non-zero exit anyway; `{"peers": []}` only on a clean read of genuinely zero peers. Strips the interface PRIVATE key and every peer PRESHARED key; emits handshake AGES not timestamps; `interfaces[]` is reported even on a zero-peer tick since it is the only source of names for the rollup gauges. Peer aliases come from the `# Name = ...` comment in `/etc/wireguard/<if>.conf`, tie-broken on the block's own `PublicKey` so a trailing comment names the NEXT peer, not the previous one), `tailscale.py` (one `tailscale status --json` -> `backend_state` verbatim, `self.key_expiry` normalized to ISO-8601 UTC (`None` = expiry DISABLED, not unknown), and tailnet ROLLUPS only -- never per-peer rows. The outcome hangs on getting a parseable status document, NOT on the exit code: a logged-out daemon is a SUCCESSFUL read carrying `NeedsLogin`, and `None` means only that the CLI/daemon could not be reached)
- **Network/connectivity**: `ip.py` (public IPv4/IPv6 via ip.fivenines.io with a 15-minute positive cache and negative-failure backoff), `ping.py` (TCP latency), `snmp.py` (SNMP device polling via net-snmp CLI tools), `mqtt.py` (persistent MQTT broker subscriptions via bundled `paho-mqtt`; the agent's first long-lived-connection collector -- a `MQTTManager` singleton keeps one client per broker alive across ticks, reconciles start/stop/resubscribe on config change only, and snapshots per-topic freshness ages under `data["mqtt"]`. RETAIN=1 deliveries update `last_message_age_s` but NEVER `last_live_seen_age_s` -- the retained-vs-live honesty the feature exists for. Reconcile is called EVERY tick from `agent._collect_metrics` so a removed `mqtt` config tears clients down; `mqtt_metrics` returns `None` when unconfigured so the key is omitted, an error/auth_error envelope -- never `None` -- on failure. `Agent._cleanup` calls `shutdown_mqtt()`. Config-pushed like `snmp_targets`; not in the COLLECTORS registry.)
- **Security scanning**: `packages.py` (installed packages via dpkg/rpm/apk/pacman/synopkg + the Windows Uninstall registry, with hash-based delta sync; the full read+hash is cached for 15 minutes (`PACKAGES_REFRESH_INTERVAL`) rather than re-read every tick, and only successful reads are cached so a transient package-manager failure retries next tick. The dpkg path (agent #138) queries `${db:Status-Status}` and drops exactly the two states dpkg guarantees have no files on disk (`not-installed`, `config-files`): `dpkg-query -W` reports every package the DB knows about, so one removed with `apt remove` rather than `apt purge` keeps its stanza -- name AND a real version -- forever and reached the CVE endpoint as if installed (one observed Ubuntu 24.04 host: 11 removed kernel ABIs, ~94% of everything reported for it, and unclearable, since `apt autoremove --purge` correctly has nothing left to remove). The other six states are inventoried -- `half-installed`, `half-configured` and the trigger states included -- because their files ARE unpacked, and the two errors are not equal: over-reporting a package costs a finding an operator can dismiss, under-reporting one DELETES a live finding for software that is still there. dpkg's status vocabulary is enumerated in FULL rather than implied, so an unrecognized status fails the read loudly instead of being guessed at in whichever direction is wrong; so do a malformed line, an empty status (a dpkg older than 1.17.11 does not know the field and silently substitutes nothing) and an on-disk row with no version. Same-(name, version) multiarch rows collapse, as in the RPM path, since the payload carries no arch. The RPM path (RHEL/CentOS/Alma/Rocky, agent #123) sends RPM's canonical `[epoch:]version-release`: the RHEL-family advisory feeds quote epoch-prefixed fix versions (`2:8.2.2637-21.el9`) and the server's comparator reads a missing epoch as 0, so an epoch-carrying package sent WITHOUT its epoch sorts below every fix forever and a fully patched host reports vulnerable. `(none)`/`0` are omitted (one canonical spelling, and the server treats them as equal), `gpg-pubkey` pseudo-packages are dropped, and same-NEVR multiarch rows collapse since the payload carries no arch. One unparseable line discards the WHOLE read -- `/packages` REPLACES the host's package set and deletes the findings that no longer match, so a silently short list is a false all-clear, while an empty read just skips the send), `docker_image_inventory.py` (OS package lists extracted from Docker **images** via the archive API `container.get_archive` -- no `docker exec`, works on stopped/never-started containers, and the only design that works under rootless, where layer files belong to subordinate UIDs a host process cannot read; dpkg + apk in phase 1, RPM reported `unsupported`. `/etc/os-release` is a symlink the GET does NOT follow, so the absolute `stat["linkTarget"]` is re-requested. The dpkg reader keys on the THIRD word of the Status triplet, never the whole `install ok installed` string -- matching the string also filters on the WANT flag, so `hold ok installed` (what `apt-mark hold` writes, a standard Dockerfile pinning idiom), `install ok unpacked` and `install ok triggers-pending` were dropped SILENTLY with no `errors[]` entry: the packages an image author deliberately froze at an old version, the ones most likely to carry a CVE, went unscanned while the image rendered as scanned and clean (agent #138). Multiarch stanzas collapse on (name, version), which also keeps duplicates from burning `MAX_PACKAGES` slots and pulling `truncated` forward. Reuses `packages.parse_os_release` + `get_packages_hash` + `_DPKG_STATUS_ABSENT` so host and image distro strings, hashes and install-status rules cannot drift. Honesty contract: a failure is NEVER an empty-and-clean payload -- every failure path records a structured `errors[]` entry, because `packages: []` with `errors: []` renders as a false "0 vulnerabilities")
- **AI/inference serving**: `inference_metrics.py` is the shared engine for the pair -- ONE bounded HTTP fetch + Prometheus text-exposition parser + never-`None` reachability envelope + `read_warnings` vocabulary, with `vllm.py` and `sglang.py` contributing nothing but an `ExpositionSpec` (their metric-name whitelist and the label dimensions their engine really emits). Fork the whitelist, never the parser. `vllm.py` (vLLM's native Prometheus `/metrics`, the serving layer above the NVIDIA GPU metrics: a reachability envelope + one whitelisted `models[]` entry per `model_name` label. The `tsdb.py` sibling -- same local HTTP fetch, same exposition parser, same never-`None` envelope, because the alert it exists for is "vLLM OOM-crashed while every GPU still reads green". Three edges: (1) a 2xx means `reachable: true` EVEN with zero `vllm:*` metrics -- `--disable-log-stats` or an upstream rename ships `models: []`, never a false outage; (2) an alias table folds version drift onto one canonical key, NEWEST name first, because a deprecation window exposes both spellings at once and summing them would double-count (upstream PR #18354 dropped the `gpu_` prefix: `gpu_cache_usage_perc` -> `kv_cache_usage_perc`, `gpu_prefix_cache_*` -> `prefix_cache_*`, `time_per_output_token_seconds` -> `inter_token_latency_seconds`); (3) remaining label dimensions (`engine`, `finished_reason`) are SUMMED, except `kv_cache_usage`, which takes the MAX -- summing a 0-1 fraction across 4 data-parallel engines ships >1 and renders as >100%. Counters and histogram `_sum`/`_count` ship RAW; a missing metric omits its key), `sglang.py` (server #893, the vLLM sibling and the other half of the AI-inference pair: same envelope, same parser, same `models[]` shape, default port 30000. Two SGLang-specific edges: (1) metrics are OPT-IN -- SGLang publishes `sglang:*` samples only under `--enable-metrics`, so a 2xx carrying zero of them is the EXPECTED stock-launch state that ships `reachable: true, models: []` and drives the server's "add --enable-metrics" hint, never an outage; (2) the rank labels (`engine_type`/`tp_rank`/`pp_rank`/`dp_rank`) REPLICATE one scheduler's reading rather than partitioning it, and the motivating fleet runs TP=8, so ALL FIVE gauges fold by MAX -- summing `gen_throughput` across 8 ranks would report 8x the real tokens/s. This is the one place the two whitelists genuinely differ: vLLM's `engine` label is data parallelism, whose counts really do add up. Counters and histogram `_sum`/`_count` still SUM and ship RAW; `token_usage`/`cache_hit_rate` ship verbatim 0-1, and `gen_throughput`/`cache_hit_rate` are GAUGES the server must never `rate()`)
- **Kernel surfaces**: `cgroup.py` (v1/v2 hierarchy detection + safe per-unit metric reads, used by `systemd.py`)
- **Log monitoring** (V1): `logs.py` (continuous per-unit error/warn signals + top fingerprints via `collect_log_signals`, wired as the `logs` collector; incident capture via `build_capture_bundle`: bounded retroactive `journalctl` slice -> redacted enriched digest; shared best-effort `redact()` for secrets/PII, also used by `systemd.py` and by `ceph.py` on the stderr it ships in error envelopes -- ceph can quote config/keyring lines into its own parse errors. `_REDACTIONS` is ORDER-SENSITIVE: the long-blob rule (base64/hex runs of >=38 chars -- 38, not 40, because a cephx key's base64 body is exactly 38 chars and must not slip under it) runs second so it pre-collapses the long unbroken runs several later rules backtrack on quadratically (measured: seconds of CPU on a 100KB token, on the watchdog-bounded loop), and a dedicated cephx rule redacts `key = AQ...` keyring material whose bare `key` label is too common for the generic assignment rule). Gated on the `journald` capability (journal read access); transport/coordination live in `log_capture.py` + `log_uploader.py` (see Core Components).

Collectors use the `@debug` decorator from `debug.py` to log execution time and results.

### Configuration

- Agent reads `TOKEN` file from config directory (default `/etc/fivenines_agent`, `~/.local/fivenines` for user install, overridable via `CONFIG_DIR`)
- Configuration is fetched from the API server on startup and includes:
  - `enabled`: whether collection is active
  - `interval`: seconds between collections (default 60)
  - Feature flags for each metric type (cpu, memory, etc.)
  - Service-specific config (e.g., redis host/port, `docker.socket_url` which drives both per-container state and metrics collection, `qemu.uri` which is subject to the agent-side libvirt URI allowlist in `qemu.py` -- the backend restricts it too, but the agent does not rely on that)
  - `request_options`: timeout, retry count, retry interval
  - `packages.scan`: triggers package inventory sync with hash-based deduplication
  - `image_inventory`: **TOP-LEVEL** truthy flag enabling Docker image OS-package extraction (uploaded to `/image_packages` off the collection loop). It must NEVER be nested under `docker`: `collectors.py` splats `config["docker"]` as `**kwargs` into `docker_metrics`, so a new nested key would raise `TypeError` on older agents, be swallowed into `data["docker"] = None`, and -- with the server's never-prune-on-null rule -- freeze container-state rows fleet-wide. Requires `docker` collection to also be enabled, since the digest set is derived from `data["docker"]["containers"]`
  - `rescan_images`: **TOP-LEVEL** bounded array of image digests the server wants re-inventoried (server issue #676), same splat-safety rule as `image_inventory`. The server sends only `api_error` digests this host runs, past its own 6h backoff; the agent drops them from `image_inventory_done` so the normal selection path re-offers them. Honoured only while `image_inventory` is on. The directive is level-triggered and untrusted, so the agent does not rely on the server for safety: it caps how much of the list it scans/honours/reads per entry, and floors repeat re-opens per digest (`rescan_min_interval`, default 1h) so a stale directive replayed during a `/collect` outage cannot treadmill re-extraction every tick
  - `vllm`: vLLM inference-server poll (`metrics_url`, `auth_header_name`, `auth_header_value`, `verify_ssl`), splatted into `vllm_metrics(**config["vllm"])`. `false` disables it; no capability gate and no OS gate (pure HTTP, the tsdb/nginx posture)
  - `sglang`: SGLang inference-server poll, same four keys and same posture as `vllm`, splatted into `sglang_metrics(**config["sglang"])`; `metrics_url` defaults to the SGLang API server port (`http://127.0.0.1:30000/metrics`). `false` disables it
  - `systemd`: unit collection config (`unit_types` as comma-separated string or list; `scan` triggers inventory delta-sync to `/systemd_inventory`)
  - `logs`: continuous log-signal collection (`units` allowlist, `signal_interval_s` window); gated on the `journald` capability
  - `capture_logs`: backend-pull incident capture command (`capture_id`, `unit`, `since`, `lines`, `expiry`); fired exactly once via the capture_id nonce + on-disk persistence, uploaded to `/logs` off the collection loop
  - `wireguard` / `tailscale`: **TOP-LEVEL plain booleans** (same splat-safety rule as `image_inventory`; both collectors take no parameters, and both are registered with `pass_kwargs=False` so a future dict value is ignored rather than splatted into a `TypeError`). `wireguard` is LINUX-ONLY -- it is in the server's `Host::WINDOWS_OMIT_CONFIG_KEYS` and is stripped for Windows agents; `tailscale` is cross-OS and never stripped. Neither is capability-GATED: a privilege failure must surface as `data["wireguard"] = null` (a collection failure the server skips), not as a missing key. `wireguard` IS capability-probed (since #144, for the dashboard's pending-capability panel) but is listed in `collectors.CAPABILITY_GATE_EXEMPT` so the probe can never omit the key
  - `mqtt`: list of brokers (`broker_id`, `host`, `port`, `tls`, `username`, `password`, `monitors[{id, topic_filter, capture_payload}]`); replaces the agent's MQTT state wholesale each tick (absent/falsy tears all clients down). Consumed as a special-case collector (like `snmp_targets`), not via the COLLECTORS registry

### Installation Types

The agent supports two installation modes:

1. **System installation**: Runs as dedicated `fivenines` user via systemd service (`fivenines-agent.service`) or OpenRC (`fivenines-agent.openrc`)
2. **User installation**: Runs as current user with helper scripts (start.sh, stop.sh, status.sh, logs.sh, refresh.sh)

User context is collected and sent with metrics to help the backend understand permission limitations.

The systemd unit is sandbox-hardened with MOUNT-NAMESPACE/ATTRIBUTE directives only: `UMask=0077` (backstops the 0600 config-dir state files), `PrivateTmp=true` and `ProtectHome=read-only`. Never add a seccomp-backed directive (`ProtectKernelTunables`, `ProtectClock`, `RestrictRealtime`, `SystemCallFilter`, ...) or `NoNewPrivileges`: on a non-root unit, seccomp makes systemd implicitly enable `no_new_privs`, which silently kills every `sudo -n` collector (SMART/RAID/fail2ban, and WireGuard since #144) fleet-wide on systemd >= 228. Also deliberately absent: `ProtectSystem=full/strict` (breaks the TOKEN swap and config-dir state; on systemd < 231 the `ReadWritePaths` exception would be silently ignored) and `MemoryDenyWriteExecute` (pynvml/libvirt load native code via ctypes/libffi). `PrivateTmp` caveats are documented in the unit and README: it hides other services' `/tmp` unix sockets from the agent, and mount-namespace setup is fatal (`226/NAMESPACE`) on OpenVZ-class kernels -- both overridable with a `systemctl edit` drop-in, which survives the updater's unit overwrite.

## Code Style

- Python 3.10+ required (compatible with 3.10-3.13)
- Code must pass: isort (black profile), black, flake8 (ignore W503, E501), mypy, bandit (skip B608)
- **ASCII-only characters in codebase** - do not use non-ASCII characters (enforced since v1.4.0)
- Test coverage must be 100%
- Use `from fivenines_agent.debug import log, debug` for logging
- Log levels: 'debug', 'info', 'error'
- Gate expensive-to-build debug messages on `debug_enabled()`: `log()` checks the level only after its argument is built, so an unguarded `json.dumps`/`str()` of a large payload costs CPU on every tick at any log level

## Important Patterns

### Subprocess Calls
Always use clean environment to avoid PyInstaller library conflicts:
```python
from fivenines_agent.subprocess_utils import get_clean_env
result = subprocess.run(cmd, env=get_clean_env(), ...)
```

### Config-Dir State Files
Create owner-only and heal a pre-existing file's mode; never plain `open(path, "w")`:
```python
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.fchmod(fd, 0o600)  # os.open's mode applies only at creation
with os.fdopen(fd, "w") as f:
    f.write(data)
```
Used by the `TOKEN` swap (`synchronizer.py`), `last_capture_id` (`log_capture.py`) and the `image_inventory_done` temp file (`docker_image_inventory.py`, where `os.replace` carries the temp file's mode onto the final path). The unit's `UMask=0077` backstops a regression, but only on systemd installs.

### Permission-Dependent Features
Check permissions before attempting operations:
```python
from fivenines_agent.permissions import get_permissions
perms = get_permissions()
if perms.get('smart_storage'):
    # Collect SMART data
```

### Signal Handling
- SIGTERM/SIGINT: Sets `exit_event` to trigger graceful shutdown
- SIGHUP: Sets `refresh_permissions_event` to re-probe capabilities without restart; also forces a full systemd inventory resend and re-detects the cached cgroup hierarchy/systemd version

### Debug Decorator
Wrap metric collection functions for automatic timing and error logging:
```python
@debug('metric_name')
def collect_metric():
    # Returns metric data
    return data
```

## Dependencies

Key dependencies:
- `psutil` (^7.2.1): Cross-platform system monitoring
- `systemd-watchdog` (^0.9.0): Systemd watchdog notifications
- `docker` (^7.1.0): Docker container monitoring
- `libvirt-python` (^11.6.0): QEMU/KVM VM monitoring
- `proxmoxer` (^2.1.0): Proxmox VE monitoring
- `certifi` (^2024.12.14): SSL/TLS certificate validation

## Binary Build Process

The `py2exe.sh` script creates a standalone Linux binary:
1. Sets up cross-compilation environment for target architecture (amd64/arm64)
2. Creates virtualenv and installs dependencies
3. Builds `libpython3.10.so` from source for PyInstaller compatibility
4. Bundles all dependencies including libvirt 6.10.0, libcrypt, libtirpc
5. Creates onedir distribution with all shared libraries included
6. Output: `./dist/linux/fivenines-agent-linux-*/`

This enables the agent to run on CentOS 7+ without system-level Python dependencies.

## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool. When in doubt, invoke the skill.

Key routing rules:
- Product ideas/brainstorming -> invoke /office-hours
- Strategy/scope -> invoke /plan-ceo-review
- Architecture -> invoke /plan-eng-review
- Design system/plan review -> invoke /design-consultation or /plan-design-review
- Full review pipeline -> invoke /autoplan
- Bugs/errors -> invoke /investigate
- QA/testing site behavior -> invoke /qa or /qa-only
- Code review/diff check -> invoke /review
- Visual polish -> invoke /design-review
- Ship/deploy/PR -> invoke /ship or /land-and-deploy
- Save progress -> invoke /context-save
- Resume context -> invoke /context-restore
