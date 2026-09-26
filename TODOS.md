# TODOS

## Block device topology (#155) -- server half not filed yet

Agent side is DONE (v1.20.0): `data["io_topology"]`, behind a new TOP-LEVEL
`io_topology` config flag that nothing sends yet, so the collector is inert until
the server enables it. The payload shape shipped as a PROPOSAL: the server may still
ask for a different one before it reads the key (one more small agent release). The
server work: copy
`tests/fixtures/io_topology_contract_payload.json` byte-for-byte into its specs,
send `io_topology: true` to agents >= 1.20.0, and replace the name rules in
`IoDeviceFilter` / `Host#stacked_io_devices` with the structural answer wherever
one is reported (count whole devices with `slaves == []` and `virtual == false`,
see the fixture's `counting_contract`, including its FALLBACK: a host whose
predicate selects no whole device -- an OpenVZ ploop container, a diskless nbd
boot -- keeps today's name rules rather than reading a zero total). That also
retires the ingestion-time `dm-`/`zd` drop and the parentless-partition guess
(`xvda1`) for Linux hosts; absent/`null`/`{}` must keep today's name rules. NVMe
native multipath is covered through `/sys/block/<head>/multipath/`, which exists
since Linux 6.15; on older kernels (Ubuntu 24.04's 6.8, Debian 13 and RHEL 10's
6.12) a multi-controller NVMe head still reads as a leaf beside its paths.

## P3: Per-collector wall-clock bound against a kernfs stall (only io_topology has one)

Found by the Codex review of #155. Under memory pressure a sysfs reader can fault
into reclaim while holding `kernfs_rwsem`, and a queued writer then blocks every
other sysfs lookup behind it -- 120-second stalls reported upstream (LKML
2026-09, Shakeel Butt, "kernfs: don't hold kernfs_rwsem across dir_emit()").
The agent reads sysfs on every tick from several collectors (`network`, psutil's
hwmon globs behind `temperatures` and `fans`), all on the collection thread, so one such
stall can outlast `WatchdogSec=90` and restart the agent. `io_topology` (#155)
is the first to bound its own read (a single-flight worker abandoned after
`TOPOLOGY_READ_TIMEOUT`); the others are not. The uniform fix is a per-collector
wall-clock bound in `collectors.collect_metrics` built on `bounded.call_bounded`
(already shared by `run_privileged`, the libvirt probe and `io_topology`), which
changes every collector's failure mode -- hence its own change. Two things it must
handle, both found reviewing #155: `run_privileged` has no single-flight, so a
wedged sudoers backend leaks one thread and one blocked root `sudo` per call site
per tick, and its per-call bounds (30s + 2s for `smartctl --scan`, then mdadm,
fail2ban, wg) can add up past `WatchdogSec=90` in one tick; and a collector that
keeps per-THREAD state -- docker's thread-local client cache -- would rebuild it
every tick if moved onto a fresh worker, so it needs its own posture.

## Proxmox backups phase 2 -- server half tracked in fivenines_server#1164

Agent side is DONE (PR #158, v1.19.0): the `data["proxmox"]["backups"]` block.
The whole feature works under the read-only `PVEAuditor` role the setup guide
already provisions -- per-guest backup volumes are read through PVE's
prune-preview endpoint (`/prunebackups`, a dryrun), so NO token change is needed
(the earlier `Datastore.Allocate` requirement was a wrong turn: it came from
reading the content listing, which filters backups per-volume; the prune preview
returns the same evidence under `Datastore.Audit`). Everything server-side is in
**fivenines_server#1164**: the ingest, the per-guest-age model, the
`proxmox_guest_backup_stale` trigger, and the byte-identical
`spec/fixtures/proxmox_contract_payload.json` copy. The only remaining
`Datastore.Allocate`/PBS-native question is the OPTIONAL later enrichment
(verification state, size) the prune preview does not carry -- not a blocker,
not a rollout decision for the core feature. Design: fivenines_server
`docs/designs/proxmox-backup-monitoring.md`.

## P1: Reconcile the server's copy of ubuntu_pro_contract_payload.json

**Tracked server-side as fivenines_server#855** -- the work happens in that repo,
this entry is the agent-side record of why.

The Ubuntu Pro fixture (#125 / server #746) was authored server-first as the
specification, with no `raw` block and its own description saying "copy the
agent's over this file BYTE-FOR-BYTE when the agent PR lands". The agent PR added
the `raw` inputs (real `pro api` envelopes + status-cache content), a
`raw_contract` and a `field_contract`, and reconciled two values that the server
copy got wrong:

- `agent_min_version` 1.15.1 (marked PROVISIONAL there) -> `1.16.1`.
- `attached_full.payload.services` `["esm-infra","esm-apps"]` ->
  `["esm-apps","esm-infra"]`. `u.pro.status.enabled_services.v1` returns
  `sorted(enabled_services, key=lambda x: x.name)` and the collector sorts again
  for stability, so the server draft's order is not one a real host can produce.

Fix: copy `tests/fixtures/ubuntu_pro_contract_payload.json` over
`fivenines-server/spec/fixtures/ubuntu_pro_contract_payload.json`, then flip the
five hard-coded `%w[esm-infra esm-apps]` assertions in
`spec/requests/api_collect_ubuntu_pro_spec.rb` to `%w[esm-apps esm-infra]`.
Nothing is broken until then -- the server reads only `scenarios.*.payload` and
its assertions are literals, not fixture-derived -- but the two copies have
drifted and the lockstep discipline says they must not.

- **Effort:** XS (human) / XS (CC)
- **Depends on:** agent PR for #125 merged
- **Files:** `fivenines-server/spec/fixtures/ubuntu_pro_contract_payload.json`,
  `fivenines-server/spec/requests/api_collect_ubuntu_pro_spec.rb` (NOT this repo)

## P1: Reconcile the server's copy of vpn_contract_payload.json

The VPN contract fixture (#127 / server #508) was authored server-first with the
scenario `raw` blocks as PLACEHOLDER STRINGS, and its own description says
"reconcile byte-for-byte with the agent PR before the agent ships". The agent PR
filled them in with the real `wg show all dump` / `tailscale status --json`
inputs, added a `raw_contract` key documenting them, and updated one sentence of
`description`. Everything the server actually READS (`agent_min_version`, the
five contract docs, and every scenario's `description` / `config` / `payload`)
was byte-identical and verified programmatically, so nothing is
broken today -- but the two copies have drifted in the agent-side inputs and the
lockstep discipline says they must not.

**Widened by #144 (agent 1.17.6).** Moving the WireGuard read to `sudo -n wg
show all dump` changed no payload byte, but it did rewrite the prose the server
copy also carries: `privilege_contract` (now the sudoers rule, not
`AmbientCapabilities=CAP_NET_ADMIN`), the CAP_NET_ADMIN clauses in
`null_contract` and `raw_contract`, and the `collection_failure` scenario
`description`. Those are keys the server reads, so the drift is no longer
confined to the agent-side inputs.

Fix: copy `tests/fixtures/vpn_contract_payload.json` over
`fivenines-server/spec/fixtures/vpn_contract_payload.json`. The server's
`spec/requests/api_collect_vpn_spec.rb` only reads `scenarios.*.payload`, so the
copy cannot break its suite.

- **Effort:** XS (human) / XS (CC)
- **Depends on:** agent PR for #127 merged (done); agent PR for #144 merged
- **Files:** `fivenines-server/spec/fixtures/vpn_contract_payload.json` (NOT this repo)

## P1: Vendor openvpn_contract_payload.json into the server (#145 / server #1103)

**Tracked server-side as fivenines_server#1103** -- the work happens in that
repo, this entry is the agent-side record of why.

Authored agent-first, so the server copy does not exist yet. The full handoff --
the byte-identical vendoring command and its sha256, the eight fixture
scenarios, `Host::WINDOWS_OMIT_CONFIG_KEYS`, the null contract, the six
decisions the issue did not settle, and the nullability the schema must allow --
is posted on that issue:
https://github.com/Five-Nines-io/fivenines_server/issues/1103#issuecomment-5646448580

Kept here rather than duplicated: the fixture at
`tests/fixtures/openvpn_contract_payload.json` is the SOURCE OF TRUTH. When it
changes, re-vendor it and update that comment -- never edit the server's copy by
hand (the Ceph #615 lesson: a hand-written copy went green against a fiction
while production read keys the agent never sent).

- **Effort:** XS (human) / XS (CC)
- **Depends on:** agent PR for #145 merged (fivenines_agent#152)
- **Files:** `fivenines-server` spec fixtures + `Host::WINDOWS_OMIT_CONFIG_KEYS`
  (NOT this repo)

## P3: Narrow the SELinux net_admin grant to the privileged child (#144)

`selinux/fivenines_agent.te` (v1.3) now grants `fivenines_agent_t`
`self:capability net_admin` plus a `netlink_generic_socket` rule, because
`sudo` changes Unix credentials but NOT the SELinux domain: with
`execute_no_trans`, the `wg` child stays confined as `fivenines_agent_t`, so
the kernel checks CAP_NET_ADMIN against that domain. Without those rules an
enforcing RHEL/Rocky host reports null however correct its sudoers rule is.

The grant is wider than the sudoers rule beside it: SELinux capability rules
are per-domain, so the agent's whole domain carries net_admin even though only
the `wg` child ever holds the Linux capability. Tightening it means a dedicated
domain for the privileged child (`type fivenines_wg_t`, a transition on
`wg_exec_t`, net_admin granted there only).

Blocked on test capability, not on design: `ci/test-selinux-vm.sh` builds and
loads the module but never exercises WireGuard, so neither the current rules
nor a transition domain are verified against real AVCs. Do this together with
an enforcing-mode WireGuard case in that VM job.

- **Effort:** M (human) / M (CC), needs an enforcing VM
- **Files:** `selinux/fivenines_agent.te`, `ci/test-selinux-vm.sh`

## P2: Unit/binary skew through the GitHub raw fallback (#144)

`fivenines_update.sh` fetches BOTH the binary and `fivenines-agent.service`
via `download_with_fallback`: R2 `latest/` first, then
raw.githubusercontent `/main`. Those two sources are versioned differently --
R2 `latest/` is populated by the tag-triggered `sync-to-r2` job, `main`
updates at merge -- so a host whose R2 fetch fails inside a merge-to-tag
window can get a NEW unit next to an OLD binary.

That combination is now load-bearing rather than cosmetic: since 1.17.6 the
unit grants no capability and the binary is what supplies the `sudo -n` path.
New unit + old binary means the old binary calls bare `wg` with no privilege
and no sudo path, so WireGuard goes dark -- and adding the sudoers rule does
NOT fix it, because that binary never uses sudo.

Fix either way round: point the unit fallback at `releases/latest/download`
(tag-gated, like the binary) instead of `/main`, or keep tagging immediately
after merge so the window stays short. The first is the real fix; the second
is what we rely on today.

Found by the adversarial pass on #146, which also corrected the claim that
unit and binary always travel together -- true only on the R2 path.

- **Effort:** XS (human) / XS (CC)
- **Files:** `fivenines_update.sh`, `fivenines_setup.sh`

## P1: Vendor the AI-inference contract fixtures into the server repo

**Tracked server-side as fivenines_server#887 (vLLM) and #893 (SGLang)** -- the
work happens in that repo, this entry is the agent-side record of why.

Unlike the ubuntu_pro and vpn entries above, these two were authored
AGENT-FIRST: `tests/fixtures/vllm_contract_payload.json` (v1.17.0) and
`tests/fixtures/sglang_contract_payload.json` (v1.17.1) are the source of truth
and the server has no copy at all yet (verified: no `sglang`/`vllm` references
in `fivenines-server/app` or `lib`, no fixture in `spec/fixtures/`).

The failure mode to avoid is specific and has bitten this pair of repos before:
hand-authoring the server's copy to match the server code instead of VENDORING
the agent's file. Ceph #615 shipped six dead gauges that way -- the ingester read
key names the agent has never sent. Vendor with:

    gh api repos/Five-Nines-io/fivenines_agent/contents/tests/fixtures/sglang_contract_payload.json \
      -q .content | base64 -d > spec/fixtures/sglang_contract_payload.json

Two agent-side decisions the server must sign off on while implementing, both
pinned in the fixtures and neither specified in the original issues:

- an optional `read_warnings` array (`foreign_labels`, `models_capped`,
  `body_truncated`, `invalid_values`, `unlabelled_series`). One rule for all of
  them: do not treat `models[]` as authoritative, and above all do not
  vanish-prune the rows missing from it.
- gauges reduce by MAX across label dimensions, not SUM. For SGLang this is ALL
  FIVE gauges (tp_rank replicates one scheduler's reading, so summing
  `gen_throughput` across 8 ranks reports 8x the real tokens/s); for vLLM it is
  `kv_cache_usage` only.

- **Effort:** XS (human) / XS (CC)
- **Depends on:** agent PRs for #133 (merged) and #135
- **Files:** `fivenines-server/spec/fixtures/{vllm,sglang}_contract_payload.json` (NOT this repo)

## P1: Re-open already-scanned image digests after the dpkg status-filter fix

**Tracked server-side as fivenines_server#1073** -- the work happens in that
repo, this entry is the agent-side record of why.

Agent #138 (v1.17.2) fixed `docker_image_inventory._parse_dpkg_status`, which
matched the whole `install ok installed` Status string and so also filtered on
the WANT flag. That silently dropped `hold ok installed` -- what `apt-mark hold`
writes, and a standard Dockerfile pinning idiom -- plus the `unpacked` and
`triggers-*` states, with NO `errors[]` entry, so the image rendered as scanned
and clean while the packages an author deliberately froze at an old version went
unscanned.

Two things have to happen for the fix to reach production data:

1. **Vendor the updated fixture.** `tests/fixtures/docker_image_inventory_contract_payload.json`
   changed in lockstep (highlight (e) reworded, a new
   `dpkg_status_with_held_and_trigger_packages` scenario). Copy it
   byte-identical, as always -- never hand-author the server's copy:

       gh api repos/Five-Nines-io/fivenines_agent/contents/tests/fixtures/docker_image_inventory_contract_payload.json \
         -q .content | base64 -d > spec/fixtures/docker_image_inventory_contract_payload.json

   `agent_min_version` deliberately stays `1.14.0`. It is the FEATURE floor the
   server gates `FEATURES_SUPPORTED_VERSIONS['docker_image_inventory']` on, so
   bumping it would switch image inventory OFF for every 1.14.0-1.17.1 agent in
   the field. The payload SHAPE did not change -- only which packages appear.

2. **Re-open the digests already inventoried.** Each digest is extracted once
   per image FOREVER (`image_inventory_done`), so every image scanned before
   1.17.2 keeps its gap indefinitely. The escape hatch already exists: send the
   affected digests in the top-level `rescan_images` array (server #676). Without
   this step the fix only ever applies to images seen for the first time.

- **Effort:** S (human) / S (CC)
- **Depends on:** agent PR for #138 merged and rolled out
- **Files:** `fivenines-server/spec/fixtures/docker_image_inventory_contract_payload.json`, the `rescan_images` emitter (NOT this repo)

## P2: Log monitoring - flat-file (non-journald) source (E2)

Deferred from `ceo-plans/2026-06-30-log-file-monitoring.md` at the Codex
cut-scope. V1 reads journald only, so services that log to their own files
(`/var/log/nginx/*.log`, apps writing files, non-systemd hosts) are uncovered.
Add a log2journal-style parser + a ring-buffer for rotation (no retroactive
read on rotating files). This is the "second subsystem" the review flagged.

- **Effort:** L (human) / M (CC)
- **Depends on:** log monitoring V1 shipped
- **Files:** `fivenines_agent/logs.py` (file source alongside journald), tests

## P3: Log monitoring - remaining V1 fast-follows

Consolidated deferrals from the same CEO plan, each a complete follow-up:
- **E1 ML edge trigger** (k-means anomaly detection on the agent) - gated behind
  a PyInstaller/BLAS feasibility spike; deterministic triggers suffice for now.
- **Local instant capture trigger** (sub-second, agent-side) - V1 uses
  backend-pull + incident-mode interval drop; the local detector is deferred.
- **Windows Event Log source** - V1 is Linux/journald only.
- **Raw posture opt-in** - V1 hardcodes `posture: "digest"`; wire the per-account
  raw flag through and enforce `max_bytes` (only meaningful for raw). E4
  log-based alerting is backend-side.

- **Effort:** varies (see plan) / mostly M (CC)
- **Depends on:** log monitoring V1 in production + demand signal
- **Files:** `fivenines_agent/logs.py`, `fivenines_agent/log_capture.py`

## P3: Log monitoring - DRY debt from pre-landing review

Two duplications flagged (confidence 4-5, deferred rather than refactor at ship):
`logs._signals_for_unit` and `logs.build_digest` share a fingerprint-grouping
loop with subtly different outputs (info counted or not, `sample` vs `excerpt`
key, top-N cap); and journald `-o json` MESSAGE parsing is duplicated between
`logs._capture_entries` and `systemd._parse_journalctl_failed`. Extract shared
helpers once the shapes stabilize.

- **Effort:** S (human) / S (CC)
- **Depends on:** nothing
- **Files:** `fivenines_agent/logs.py`, `fivenines_agent/systemd.py`, tests

## P1: Hourly re-send TTL for stuck-failed unit drilldowns

Deferred from plan `2026-05-04-systemd-services.md` (ship gate decision). The
failure drilldown is debounced by `(NRestarts, ActiveEnterTimestamp)` signature,
so a unit that stays failed with an unchanged signature sends its journal tail +
reverse-deps (the latter only on systemd >= 230) exactly once. The plan called for a 1-hour TTL that forces a
re-send so the backend periodically refreshes the evidence. Marginal in
practice (a dead unit's err-priority journal rarely changes), which is why it
was deferred rather than reopening the reviewed debounce logic at ship time.

- **Effort:** S (human) / S (CC)
- **Depends on:** systemd module shipped
- **Files:** `fivenines_agent/systemd.py` (`_is_newly_failed` LRU entry gains a timestamp + TTL check), tests

## P2: Inventory/packages POST retries stall the collection thread during API outages

`synchronizer._post` retries 3x with backoff (~30-60s worst case) and both
`systemd_inventory_sync` and `packages_sync` call it synchronously from the
collection thread. During an API outage with an unacknowledged inventory hash,
every tick re-attempts the send and stalls collection for the retry duration.
Shared architecture with packages_sync (pre-existing pattern), so fix both at
once: either single-attempt sends for delta-synced payloads (the per-tick hash
recheck already provides retry semantics) or dispatch through the synchronizer
thread.

- **Effort:** M (human) / S (CC)
- **Depends on:** nothing (architecture change, touch synchronizer + agent)
- **Files:** `fivenines_agent/synchronizer.py`, `fivenines_agent/agent.py`, tests

## P3: Generalized resilience to an unshowable name in the bulk show

A single unit name that `systemctl show` rejects fails the whole bulk fetch
(exit non-zero -> `_run_subprocess` drops all stdout), blacking out health +
inventory for the host every tick. Bare template units were the known trigger
and are now filtered (`_is_template_unit`), and `list-units` only yields
concrete showable units, so the surface is showable in practice. But if any
other unshowable name ever appears, the blast radius is the whole host. Harden
by isolating the bad name on a `cli_error` -- bisect the failing chunk and drop
the offending unit(s) -- instead of failing the entire fetch. Locale-independent
(no error-message parsing); bounded at log2(chunk) retries.

- **Effort:** M (human) / S (CC)
- **Depends on:** nothing
- **Files:** `fivenines_agent/systemd.py` (`_show_bulk`), tests

## P3: Docker image caching for CI resilience

Mirror the 14 distro base images used in `test-distro-matrix` to ghcr.io or use
a Docker pull-through cache. Currently, all distro tests pull from Docker Hub
directly. A Docker Hub outage or rate-limit event would block the entire CI
pipeline.

- **Effort:** M (human) / S (CC)
- **Depends on:** #30 (distro regression testing) shipping first
- **Files:** `.github/workflows/build-release.yml`

## P2: Promote Rocky 10 to blocking

The `rockylinux:10` test matrix entry runs with `allow_failure: "1"` because the
Docker image does not exist yet. When Rocky Linux 10 GA ships and the Docker image
is available on Docker Hub, remove `allow_failure` from the matrix entry so that
RHEL 10 generation regressions block releases.

- **Effort:** S (human) / S (CC)
- **Depends on:** Rocky Linux 10 GA release
- **Files:** `.github/workflows/build-release.yml` (remove `allow_failure: "1"` from rockylinux:10 entry)

## P3: User-mode systemd units (systemctl --user)

Extend the systemd collector to optionally include user-mode systemd units
(`systemctl --user list-units`). Deferred from the initial systemd module ship
because user-mode systemd is rare on monitored fleets (mostly servers, not
developer desktops). Surface only if a customer asks for per-user service
visibility.

- **Effort:** M (human) / S (CC)
- **Depends on:** systemd module shipping first
- **Files:** `fivenines_agent/systemd.py` (add per-user invocation loop), `fivenines_agent/permissions.py` (probe), tests

## P3: Event-driven D-Bus subscription for systemd state transitions

The 10x version of systemd monitoring: subscribe to `org.freedesktop.systemd1`
D-Bus signals and push state transitions in real-time, eliminating polling lag
and dropping inventory cost to zero between changes. Rejected for the initial
ship because `pystemd` / `dbus-python` add native build deps that conflict with
the PyInstaller bundling story (CentOS 7+ binary target). Worth revisiting if
the binary build constraint changes (e.g., dropping CentOS 7 support, or moving
to a different bundler).

- **Effort:** L (human) / M (CC)
- **Depends on:** binary build constraints relaxing OR pystemd alternative emerging
- **Files:** new `fivenines_agent/systemd_events.py`, `pyproject.toml`, `py2exe.sh`

## P4: Additional systemd unit types (.mount/.path/.swap/.slice/.scope)

Deferred from the initial systemd ship. Already reachable today WITHOUT a code
change: the backend can set `systemd.unit_types` to any comma-separated list
(the collector normalizes list/tuple config too). This entry exists to decide
whether any of these types should join the DEFAULT set once real-fleet payload
sizes are known.

- **Effort:** S (human) / S (CC)
- **Depends on:** payload-size data from fleets running the shipped defaults
- **Files:** `fivenines_agent/systemd.py` (`DEFAULT_UNIT_TYPES`)

## P4: Boot-time analysis via systemd-analyze blame

Deferred from the initial systemd ship (plan listed it as a possible drilldown
extension). `systemd-analyze blame`/`critical-chain` would let the backend show
slow-boot culprits. One-shot data per boot, so it belongs in static/boot-time
collection rather than the per-tick loop.

- **Effort:** M (human) / S (CC)
- **Depends on:** product signal that boot-time analysis matters to customers
- **Files:** `fivenines_agent/systemd.py` (one-shot collection), `fivenines_agent/agent.py` (static data), tests

## P3: Docker events API for short-lived container capture

The container-state collector (server #492) polls `containers.list(all=True)` once
per tick, so a container that starts and exits (or is `--rm`'d) entirely between
two ticks is never observed -- its death, exit code, and OOM status are invisible.
The 10x version subscribes to the Docker events stream (`client.events()`) and
records terminal transitions as they happen, eliminating the polling blind spot.
Deferred from the initial ship because an events subscription is a persistent
connection with its own lifecycle/reconnect handling (a different shape from the
per-tick poll loop) and the poll already covers every container that lives at
least one interval -- the common case. Documented as a known limitation in the
`docker.py` module docstring.

- **Effort:** L (human) / M (CC)
- **Depends on:** container-state collector shipped (done, 1.11.0)
- **Files:** new events-stream path in `fivenines_agent/docker.py` (or a sibling), `fivenines_agent/agent.py` (subscription lifecycle), tests

## P3: OOM detection journal-parse fallback for cgroup v1

The systemd module ships OOM kill detection via cgroup v2 `memory.events`.
On cgroup v1 and hybrid hosts, OOM count is reported as null. If backend
alerting needs v1 OOM coverage, add a journal-parse fallback that scans
`journalctl -k` for "Killed process" entries and correlates by PID/unit.
Avoided in initial ship because journal-parse is fragile and adds ongoing
subprocess cost; deferred until a concrete backend requirement appears.

- **Effort:** M (human) / S (CC)
- **Depends on:** backend signal that v1 OOM coverage matters
- **Files:** `fivenines_agent/systemd.py` (add fallback path), tests, fixtures

## P4: Finer interface_type classification (bond / vlan / paravirtual)

The issue #50 `interface_type` is a coarse three-way heuristic: bridge (has
`bridge/`), physical (has a `device` node), else virtual. That mislabels bond
and vlan masters -- which can carry the host's real uplink -- as "virtual", and
labels paravirtual NICs (virtio-net, Xen, Hyper-V, SR-IOV VFs) as "physical".
Not a correctness bug: saturation keys off `network_link_speed_bps` presence,
not `interface_type` (documented in the collector + the contract fixture), so a
mislabel only affects backend grouping. If the backend wants precise grouping,
read `bonding/` / vlan markers (or `uevent` DEVTYPE) and widen the enum. Deferred
as an enhancement beyond the bridge-vs-physical ask in #50.

- **Effort:** S (human) / M (CC)
- **Depends on:** a backend grouping requirement that needs bond/vlan precision
- **Files:** `fivenines_agent/network.py` (`_interface_type`), `tests/test_network.py`, `tests/fixtures/network_contract_payload.json`

## P3: MQTT collector - v1 protocol/transport fast-follows

Issue #92 v1 deliberately scoped MQTT to 3.1.1 over TCP/TLS with QoS 0 + clean
session, username/password auth, subscribe-only. Deferred, each a complete
follow-up gated on demand:
- **MQTT 5** - richer reason codes + subscription options; `_connect_status`
  already normalizes v3/v5 reason codes, so this is mostly a protocol flag + a
  callback-signature pass.
- **WebSockets transport** - `transport="websockets"` for brokers behind a
  reverse proxy / cloud MQTT (HiveMQ Cloud, AWS IoT over WSS).
- **mTLS client certificates** - `tls_set(certfile=, keyfile=)` for brokers that
  require a client cert; needs a secret-delivery path for the key material.
- **`tls_insecure` opt-in** - v1 always verifies the broker cert (system CAs +
  hostname). Self-signed customer brokers need an explicit per-broker
  insecure/`ca_certs` override, wired from the dashboard.
- **Active liveness probe (publish)** - v1 never publishes; an optional
  round-trip publish to a canary topic would distinguish "broker up but device
  silent" from "broker reachable" more sharply than passive freshness.
- **SUBACK-verified arming** - v1 arms `subscribed_at` on the subscribe() return
  code (NO_CONN skips the arm; the honest signal we have). It does NOT wait for
  the `on_subscribe` SUBACK, because Mosquitto deliberately returns SUBACK
  success for ACL-denied filters and then silently drops deliveries, so
  client-side "am I really subscribed" detection is structurally unreliable. The
  server's exact-topic staleness (a topic that never arrives) is the real safety
  net; a granted-QoS check via on_subscribe is a marginal add if a customer ACL
  setup ever needs it.

- **Effort:** varies / mostly M (CC)
- **Depends on:** MQTT v1 in production + demand signal (e.g. a customer broker
  that needs WSS or a self-signed cert)
- **Files:** `fivenines_agent/mqtt.py` (`_BrokerClient._build_client`,
  `_connect_status`), `tests/test_mqtt.py`, `tests/fixtures/mqtt_contract_payload.json`

## P2: Resolve /image_packages merge semantics before the language-ecosystem phase

The image-inventory payload carries `ecosystem: null` ("the image's OS
ecosystem") so a later phase can send `{"name":"lodash","version":"4.17.20",
"ecosystem":"npm"}` on the same endpoint without a contract break. Two things are
unresolved and BLOCK that phase:

- **Merge vs replace.** If a POST replaces all packages for an `image_id`, the
  npm POST would wipe the OS packages -- and the agent will never re-send them,
  because `mark_done` is once-per-digest-forever. Upserting by
  `(name, version, ecosystem)` avoids that.
- **`packages_hash` excludes `ecosystem`.** It is `sha256` over `name=version\n`
  only (reused verbatim from the host `/packages` path for byte-compatibility),
  so once `ecosystem` is populated two different sets hash identically. Either
  fold ecosystem into a distinct image-side hash or stop using `packages_hash` as
  a set identity.

Both are documented in the shared fixture's `packages_contract` block; this TODO
is to actually decide them with the server side.

- **Effort:** S (human) / S (CC)
- **Depends on:** server `/image_packages` ingester shipped
- **Files:** `fivenines_agent/docker_image_inventory.py` (`_payload`), `tests/fixtures/docker_image_inventory_contract_payload.json`, server ingester

## P2: packages_sync has no agent-side memory of what it last sent

Raised by the red-team pass on #138. The only stop condition for a re-POST is
the server echoing `last_package_hash` back through a `/collect` response --
`grep` confirms it is read in exactly one place and stored nowhere on the agent.

Normally harmless, but #138 ships on a day when EVERY Debian/Ubuntu host's hash
is guaranteed to change at once. Any host whose `/collect` config echo lags --
queue backlog, API degradation, or the very `/packages` load this release
creates -- re-POSTs its identical full inventory on the next tick, and the next.
The load is self-reinforcing rather than decaying, and there is no jitter
anywhere in the agent (`grep -rn 'random|jitter' fivenines_agent/` returns
nothing): `_post` retries are deterministic linear backoff and `_wait_interval`
is a fixed period.

`packages_sync` also runs synchronously on the collection loop that
`WatchdogSec=90` bounds, which is the same exposure the P2 entry below
("Inventory/packages POST retries stall the collection thread") already
describes -- this change is what will exercise it fleet-wide.

Cache the last successfully-POSTed hash agent-side (in-memory breaks the
per-tick loop; on-disk under `config_dir` survives restarts) and treat the
server's `last_package_hash` as an override that can force a resend. Add jitter
to `_post`'s retry interval. Longer term, move `packages_sync` off the
collection loop through the `QueueUploader` pattern.

- **Effort:** S (human) / S (CC)
- **Depends on:** nothing
- **Files:** `fivenines_agent/packages.py` (`packages_sync`), `fivenines_agent/synchronizer.py` (`_post`)

## P3: Package-reader hardening leftovers from the #138 review

All three are PRE-EXISTING, all lean toward over-reporting (never a false
all-clear), and none is reachable from real package-manager output -- which is
why they were left out of #138 rather than widening a security fix. Recorded so
the asymmetries are a decision, not an accident.

- `_get_packages_rpm` still uses `if not line.strip(): continue`, which silently
  skips a `"\t\t"` row and ships a short list. The dpkg twin was changed to
  `if not line:` in #138 precisely because `strip()` eats tabs. rpm never
  renders an empty `%{NAME}`, so it is unreachable today.
- `docker_image_inventory._parse_dpkg_status` silently skips a stanza whose
  `Status:` is not exactly three words or which has no `Version:` line -- a
  partial list with an empty `errors[]`, where the host path aborts loudly. dpkg
  always writes a three-word Status.
- The host reader does not scrub control characters out of name/version the way
  the image path does via `_scrub`, so an ESC/NUL byte in a dpkg field would
  reach the `/packages` payload verbatim.

- **Effort:** S (human) / S (CC)
- **Depends on:** nothing
- **Files:** `fivenines_agent/packages.py`, `fivenines_agent/docker_image_inventory.py`

## P2: Surface package-inventory staleness (a host that stopped sending)

Raised by the adversarial pass on #123. `packages_sync` deliberately sends
NOTHING when a package read is untrustworthy (a corrupt rpmdb, a format change,
a broken header): stale-but-honest inventory beats a short list, because
`Osv::ScanHostJob` deletes the findings that no longer match and a dropped row
reads as "fixed". The cost is that such a host goes QUIET, and today nothing
notices -- the server ignores the agent's `_telemetry` block entirely, and
`last_packages_received_at` is only read to decide whether to re-request a
scan, never rendered.

So the honest failure mode is currently an invisible one. The data already
exists server-side; it needs surfacing: flag a host whose
`last_packages_received_at` is older than N days on /security (and/or ingest
`_telemetry[*].errors`, which is where the agent already reports the reason).

- **Effort:** S (human) / S (CC)
- **Depends on:** nothing
- **Files:** fivenines_server (`/security` view, `Host#last_packages_received_at`), optionally `_telemetry` ingestion

## P2: Verify RHEL-family CVE scanning end to end on a live host

Agent #123 shipped epoch-qualified `rpm -qa` collection, and the server side
(#736 stack, fivenines_server #739-#742) has been merged and dormant for a
while. The only part of the issue that could not be verified pre-merge is the
one that needs both halves running: a real RHEL/Alma/Rocky host with a known
vulnerable package should produce findings on /security, and a package whose
only fix is EUS/AUS-gated should render "requires subscription" rather than a
bare affected.

The comparator half WAS verified locally by running the server's own
`Osv::PackageScanner.version_compare` against the agent's output: a patched
host reads VULNERABLE under the old epoch-less format and clear under the new
one. What remains is the live round trip.

Note the one-time effect on upgrade: every RHEL-family host's `packages_hash`
changes on the first tick after 1.17.x (epochs enter the string), so each one
re-POSTs its inventory once and re-scans. Expected, and it is what clears the
stale false positives.

- **Effort:** S (human) / S (CC)
- **Depends on:** agent 1.17.x reaching a RHEL host
- **Files:** none in this repo -- verification only (`/security` page, `Osv::SecurityScan`)

## P3: RPM package extraction for image inventory (phase 1.5)

Phase 1 covers dpkg + apk. RPM images (AlmaLinux, Rocky, RHEL, Fedora, Amazon
Linux, openSUSE) currently report `unsupported_distro` with a reason -- honest,
but unscannable. `rpmdb.sqlite` retrieves identically via the archive API, but
the rows hold binary RPM header blobs that need decoding (tags 1000/1001/1002/
1003), and RHEL 8-era images use Berkeley DB instead. Tracked as a separate issue
per #101.

- **Effort:** M (human) / M (CC)
- **Depends on:** image inventory phase 1 shipped
- **Files:** `fivenines_agent/docker_image_inventory.py` (`_RPM_IDS` branch, a new parser), tests, fixture

## P4: package_cap fixture scenario for the image-inventory contract

`errors[].type` includes `package_cap` (the package list was TRUNCATED to 2000,
so `packages` is a prefix and the server must not render the scan as complete).
It is declared in the fixture's `errors_contract` and pinned by a drift test, but
it has no `scenarios` entry, because a 2001-package fixture would bloat the file
the server vendors byte-identical. If the server team wants a concrete example,
generate one at spec time from the declared enum rather than committing it.

- **Effort:** S (human) / S (CC)
- **Depends on:** nothing
- **Files:** `tests/fixtures/docker_image_inventory_contract_payload.json`, `tests/test_docker_image_inventory.py`

## P3: Bound the QEMU collector's libvirt connection with a timeout

`QEMUCollector._connect` calls `libvirt.openReadOnly` with no deadline, on the
collection thread. The permissions probe already wraps its own open in a worker
with `LIBVIRT_PROBE_TIMEOUT` (3s) for exactly this reason: a wedged libvirt
stack (socket activation, daemon handshake, polkit, NSS) blocks indefinitely,
and the collection loop is bounded by `WatchdogSec=90`.

Agent #142 closed the backend-steerable half of this by constraining
`?socket=` to libvirt's own socket directories, so a hostile config can no
longer point the agent at a peer that reads and waits (docker.sock, a
socket-activated service). What remains is the honest case: a real libvirt that
hangs. The fix mirrors `_can_access_libvirt` -- worker thread, hard timeout,
single-flight so a hung open cannot leak one thread per tick -- and reports
`None` on timeout (a collection failure, which the collector now distinguishes
from `[]`).

- **Effort:** M (human) / S (CC)
- **Files:** `fivenines_agent/qemu.py`, `tests/test_qemu.py`

## P3: Thread the configured QEMU URI through the capability probe

`permissions._can_access_libvirt` opens `DEFAULT_LIBVIRT_URI` while the
allowlist accepts `/session`, `?socket=` and `?mode=`. `collectors._is_capability_gated`
skips the `qemu` collector whenever the default socket does not open, so a host
configured with a non-default URI is gated out even when its own URI works;
conversely the capability reads AVAILABLE while the configured URI fails every
tick. The docker precedent already exists: `set_docker_socket_url` pushes the
configured endpoint into the probe each tick. Doing the same for `qemu.uri`
means routing the configured value through `qemu.libvirt_uri_rejection` in the
probe as well (the check removed in #142 as unreachable becomes reachable).

- **Effort:** M (human) / S (CC)
- **Files:** `fivenines_agent/permissions.py`, `fivenines_agent/agent.py`, `tests/test_permissions_recheck.py`

## P2: Move the MSI Authenticode signing into the `release` environment (#63)

`build-windows-amd64` runs for every `feature/**`, `fix/**` and `release/**`
push and reads `AZURE_CLIENT_SECRET` and the other Trusted Signing secrets as
repository secrets. They are not configured yet, so nothing leaks today -- but
the day #63 adds them, any branch push can get an arbitrary binary
Authenticode-signed with the company certificate, which is exactly what #159
moved the release signing key and the R2 credentials away from.

Fix before adding the secrets: sign the MSI in a job that declares
`environment: release` (tag builds only) -- a small job after
`build-windows-amd64` that downloads the MSI artifact, signs it and re-uploads
it -- and store the six Azure secrets in that environment, never at repository
level. CONTRIBUTING.md ("Workflows") already states the rule.

- **Effort:** S (human) / S (CC)
- **Files:** `.github/workflows/build-release.yml`

## P2: Refuse to publish an older release over a newer one on R2 `latest/`

`sync-to-r2` writes whatever tag run reaches it into `latest/`, the prefix
every installer and updater reads. Re-running an old tag's workflow, or a
`workflow_dispatch` on an old `v*` tag, rolls every future install back to that
release with a perfectly valid signature. The `r2-latest` concurrency group
only serialises writers, and GitHub keeps one pending job per group, so a third
queued sync replaces the second -- possibly the newer one.

Fix: before touching `latest/`, refuse unless `GITHUB_REF_NAME` is the highest
`v*` tag (`git ls-remote --tags origin 'v*'` sorted with `sort -V`), and upload
`SHA256SUMS` + `SHA256SUMS.sig` last so a partial sync never pairs one release's
manifest with another's binaries. The versioned `v<version>/` prefix can keep
accepting any tag.

- **Effort:** S (human) / XS (CC)
- **Files:** `.github/workflows/build-release.yml`

## P3: Confirm the dependency graph sees `ci/requirements/`

The hash-pinned build tools (`ci/requirements/*.txt`, #159) are regenerated by
hand -- Dependabot ignores `uv pip compile --python-version` -- so their only
vulnerability signal is the dependency graph's alerts. Their file names
(`build-tools.txt`, ...) may not match what GitHub parses as a pip manifest.
After merge, check Insights > Dependency graph lists them; if it does not,
rename them to `*requirements*.txt` or add a scheduled
`pip-audit --require-hashes -r ci/requirements/<file>.txt` job. (Most of the
effective build environment is also in `poetry.lock`, which is scanned: the
bake's `poetry install` re-syncs poetry's own dependencies to the lock.)

- **Effort:** XS (human) / XS (CC)
- **Files:** `ci/requirements/`, `.github/workflows/`

## Completed

### P3: Nightly distro matrix runs

`build-release.yml` now has a weekly `schedule` trigger (#159): a cold build
of `main`, the builder images rebuilt without cache, with no release published.
`test-distro-matrix` has no job-level condition, so it runs on that schedule
too, against the distro images Docker Hub serves that week. An upstream distro
change (a new Alpine minor changing BusyBox behavior, a new Ubuntu release
changing adduser flags) that breaks the installer or the binary now shows up in
a scheduled run before it reaches users. Weekly rather than nightly.

**Completed:** v1.19.1 (2026-09-26)

### P1: Verify the startup definitions against the signed manifest (#154)

The installers verified the agent tarball but downloaded the systemd unit, the
OpenRC init script and the UNRAID boot script unverified -- on the GitHub
fallback straight from the `main` branch, which no manifest can cover -- and
wrote them to their final path. A compromised download server could not touch
the verified binary but could still choose the `ExecStart` that runs as root
at every boot. Those three are published release assets now, covered by the
same signed `SHA256SUMS`; `install_verified_release_file` stages them in a
private work dir, verifies, then lands them through a sibling temp file inside
the destination directory (chmod + restorecon there, atomic same-filesystem
rename), so a refusal leaves the existing definition untouched and a crash
cannot leave a truncated unit. The raw main-branch URL is gone from all four
installers, and `ci/test-signing.sh` (64 checks) plus a second list in
`ci/build-scripts.sh` keep both the helper and its call sites honest.

**Completed:** v1.18.1 (2026-09-21)

### P1: Fail closed when the release signature cannot be checked (#154)

`verify_sums_signature` now distinguishes "no openssl on this host" (3, fatal)
from "no key embedded in this installer" (2, the key-rotation escape hatch,
still checksum-only with a warning). `FIVENINES_ALLOW_UNSIGNED=1` is the
documented opt-out, and minimal Alpine images need `apk add openssl`.
`verification_preflight` runs that check BEFORE the update script stops the
agent -- the failure is deterministic per host, so discovering it after the
stop would leave every minimal-image host unmonitored on every update -- and a
refusal after the stop now restarts the agent on the existing definition
instead of exiting with it down.

**Completed:** v1.18.1 (2026-09-21)

### P1: Locally enforced journal allowlist + a documented way to remove journal access

`journal_units.allow` in the config dir is the host owner's veto over which
unit journals the agent may read. It is intersected with the backend's list,
never unioned, and bounds every journal read: log signals, incident capture,
the `_capture_entries` choke point and the systemd failure drilldown. Absent
file means no local policy (existing installs are unchanged); present-but-
empty, unreadable, a dangling symlink, a non-regular file and an oversized
file all mean "read nothing", loudly -- an oversized file is refused rather
than truncated, because a `*.service` cut at the byte cap becomes `*` and
would WIDEN the policy. A glob in a name the SERVER sent is refused outright,
since `journalctl -u` expands globs itself. Refusals ship in the payload as
`refused_units`, so a unit that was never read cannot render as a unit with
zero errors. For hosts that need no log monitoring at all, the unit and the
README document dropping `SupplementaryGroups=systemd-journal` with a
`systemctl edit` drop-in that survives the updater.

**Completed:** v1.18.1 (2026-09-21)

### P2: Stop logging IPv6 lookup failures on hosts that have no IPv6

`get_ip(ipv6=True)` checked nothing about the host, so a v4-only box (any
container on a v4-only bridge) paid a DNS lookup plus a connect that could
only fail, every backoff window, forever -- and logged it at error level. The
interface list is now consulted first, so there is no network work at all, and
the failure latch is keyed on the KIND of failure rather than a bare counter:
the first of each kind is loud, repeats are debug, and a genuinely different
failure (`ip.fivenines.io returned a non-IPv4 body` -- a captive portal) is
never buried behind an earlier connect error.

**Completed:** v1.18.1 (2026-09-21)

### P1: QEMU collector - enforce an agent-side allowlist of libvirt URI schemes (#142)

A libvirt URI selects a TRANSPORT as well as a hypervisor, and `ext` runs a
local command while `ssh`/`libssh`/`tcp`/`tls` spawn SSH or dial a network
host -- independently of `openReadOnly()`. `qemu.libvirt_uri_rejection` now
refuses anything but `qemu:///system|session` and `qemu+unix:///system|session`
(no authority, `?socket=` inside a libvirt socket directory, `?mode=` from a
fixed set, no `;`, printable decoded values, 512-char cap) BEFORE any libvirt
call; a refused URI logs its reason only -- never the URI -- and reports
`None`. The collector also reports `None` on a failed open or enumeration
(`[]` now means libvirt listed zero domains), and sets `LIBVIRT_AUTOSTART=0`
at import so a `qemu:///session` URI never forks the session daemon.

**Completed:** v1.17.5 (2026-09-11)

### P3: Hoist net_if_addrs() out of the per-interface loop in interfaces()

`interfaces()` called `psutil.net_if_addrs()` once per interface (a full
getifaddrs walk each time -- O(N^2), dominant per-tick cost on Proxmox hosts
with thousands of veth/tap interfaces). The map is now computed once before
the loop; `test_interfaces_skips_when_net_if_addrs_raises` was replaced by
`test_interfaces_empty_when_net_if_addrs_raises` (single-fetch semantics) plus
a call-count pin (`test_interfaces_calls_net_if_addrs_once`).

**Completed:** v1.17.3 (2026-09-07)
