"""Docker container-state + metrics collector.

Emits ``data["docker"] = {"containers": {<full-64-hex-id>: {...}}}``.

Every container -- any status, from its FIRST sighting -- ships an unconditional
identity + state block (name, image, status, exit_code, oom_killed,
restart_count, started_at/finished_at, health). Running containers additionally
ship resource stats (CPU/memory/block-I/O/networks), but only once a previous
stats sample exists (CPU percent needs a delta), so a running container's first
tick is state-only too. This is the contract the fivenines-server DockerContainer
ingester relies on; see tests/fixtures/docker_contract_payload.json.

Failure vs empty are distinct signals:

- ``docker_metrics`` returns ``{"containers": {...}}`` on success. ``{}`` means
  GENUINELY zero containers -- the server may prune every row for the host.
- ``docker_metrics`` returns ``None`` (JSON ``"docker": null``) when collection
  fails (daemon unreachable, connect error, container-list error). The server
  must never prune on this -- a daemon hiccup is not "all containers removed".

Known limitation: a container that starts and exits (or is ``--rm``'d) entirely
between two ticks is never observed. Capturing those needs the Docker events
API, which is a later phase.
"""

import os
import threading
import time

import docker
import requests

from fivenines_agent.debug import debug, log

# The rootful socket docker-py falls back to when DOCKER_HOST is unset.
DEFAULT_SOCKET_PATH = "/var/run/docker.sock"

# Per-request timeout for the Docker SDK. docker-py's default is 60s per API
# call, and one tick makes 1 list + a reload (and stats, for running
# containers) per container, all serial -- two wedged calls at the default
# already exceed the systemd watchdog (90s). 10 rather than 5: the one
# containers.list() per tick can legitimately take several seconds on a
# loaded daemon with a large container graveyard, and a too-tight timeout
# there would ship docker=null on every tick (frozen container rows) for as
# long as the load lasts. Three wedged calls still trip COLLECT_DEADLINE
# well under the watchdog.
CLIENT_TIMEOUT = 10

# Wall-clock budget for one collection pass. When exceeded we return None (a
# collection failure the server never prunes on) rather than a PARTIAL
# container map, which the server would read as the missing containers having
# been removed. Bounds a merely-slow (not down) daemon: 500 containers at
# 200ms/call is ~100s+ of tick time without this. 25, and checked TWICE per
# iteration (loop top + after reload): one iteration makes up to three
# CLIENT_TIMEOUT-bounded calls (reload, image inspect, stats), so a top-only
# check could overshoot by ~3x CLIENT_TIMEOUT; with the mid-iteration check
# the worst case is deadline + ~2 calls, comfortably under the 90s watchdog
# alongside the other collectors.
COLLECT_DEADLINE = 25

# Per-thread cached client. The collection loop and the image-inventory
# uploader thread both call get_docker_client; docker-py rides on a
# requests.Session, so each thread keeps its own client rather than sharing
# one. Rebuilding per call paid a client construction PLUS an API version
# negotiation round-trip (docker-py resolves the server version on first use
# with version=None) on every tick, and the old client's connection pool was
# abandoned to the GC.
_local = threading.local()


def _client_key(socket_url):
    """Cache key: the inputs that change which endpoint we would dial."""
    return (
        socket_url,
        os.environ.get("DOCKER_HOST"),
        os.environ.get("XDG_RUNTIME_DIR"),
    )


def invalidate_docker_client():
    """Drop this thread's cached client so the next call reconnects fresh.
    Called after daemon-level failures; requests would reconnect transparently
    for most errors, but a full rebuild also re-runs socket resolution (the
    daemon may have moved, e.g. rootless restart with a new XDG dir)."""
    client = getattr(_local, "client", None)
    _local.client = None
    _local.client_key = None
    if client is not None:
        try:
            client.close()
        except Exception:
            pass


# Per-tick container cap. Running containers are always kept first; the rest are
# taken newest-first (by Created). Bounds the payload on hosts with a large
# graveyard of exited containers.
_MAX_CONTAINERS = 500

# Docker serializes the Go zero time for a never-set State timestamp as this
# exact string (a "created" container has never started/finished). Normalized
# to null so the server does not read it as a real 1-CE date.
_ZERO_TIMESTAMP = "0001-01-01T00:00:00Z"

# Last stats sample per running container id, for the CPU-delta warm-up. Pruned
# every tick to the set of containers actually seen, so removed containers do
# not leak entries.
previous_stats = {}

# Process-once guard for the container-cap warning (avoids per-tick log spam on
# a host that is chronically over the cap).
_cap_logged = False


def rootless_socket_url():
    """unix:// URL for $XDG_RUNTIME_DIR/docker.sock when that is the only socket
    available, else None.

    docker.from_env() reads DOCKER_HOST but has NO XDG_RUNTIME_DIR fallback, so
    without this a rootless host whose operator never exported DOCKER_HOST
    resolves to /var/run/docker.sock and fails to connect -- while the permission
    probe (which does check XDG) reports the docker capability AVAILABLE. That
    split is worse than either behaviour alone: the collector is gated on a
    capability that lies. Returning None for every other case keeps
    docker.from_env() in charge, so DOCKER_HOST + its TLS env vars
    (DOCKER_TLS_VERIFY, DOCKER_CERT_PATH) behave exactly as before."""
    if os.environ.get("DOCKER_HOST"):
        return None  # from_env handles it, including the TLS env vars
    if os.path.exists(DEFAULT_SOCKET_PATH):
        return None  # rootful socket present: the normal path
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if not xdg:
        return None
    # Joined POSIX-style on purpose, not with os.path.join: a Docker unix socket
    # path is always POSIX, and ntpath.join would produce
    # "/run/user/1000\\docker.sock" when the suite runs on Windows.
    candidate = f"{xdg.rstrip('/')}/docker.sock"
    if not os.path.exists(candidate):
        return None
    return f"unix://{candidate}"


def get_docker_client(socket_url=None):
    key = _client_key(socket_url)
    cached = getattr(_local, "client", None)
    if cached is not None and getattr(_local, "client_key", None) == key:
        return cached
    # Endpoint inputs changed (or first call): drop any stale client first.
    invalidate_docker_client()
    try:
        if socket_url:
            client = docker.DockerClient(base_url=socket_url, timeout=CLIENT_TIMEOUT)
        else:
            rootless = rootless_socket_url()
            if rootless:
                log(f"Connecting to rootless Docker socket {rootless}", "debug")
                client = docker.DockerClient(base_url=rootless, timeout=CLIENT_TIMEOUT)
            else:
                client = docker.from_env(timeout=CLIENT_TIMEOUT)
    except docker.errors.DockerException as e:
        log(f"Error connecting to Docker daemon: {e}", "error")
        return None
    _local.client = client
    _local.client_key = key
    return client


def _clean_name(name):
    """Container name without Docker's leading slash."""
    if not name:
        return None
    return name.lstrip("/")


def _normalize_timestamp(value):
    """Pass a Docker RFC3339 timestamp through untouched, mapping the Go
    zero-value (and any empty value) to None."""
    if not value or value == _ZERO_TIMESTAMP:
        return None
    return value


def _health(state):
    """Health status from a HEALTHCHECK, or None when none is defined.

    Null means "not applicable" (no HEALTHCHECK), never a good/bad signal.
    """
    health = state.get("Health")
    if not isinstance(health, dict):
        return None
    return health.get("Status")


def _image_tags_and_digests(client, image_id, cache):
    """Tags + repo digests for an image, fetched once per image id per tick.

    Containers share images, so the fetch is memoized by image id. A missing
    image (deleted mid-tick) yields empty lists rather than crashing the entry.
    """
    if image_id in cache:
        return cache[image_id]

    result = {"image_tags": [], "image_repo_digests": []}
    try:
        image = client.images.get(image_id)
        result["image_tags"] = image.tags or []
        result["image_repo_digests"] = image.attrs.get("RepoDigests", []) or []
    except Exception as e:
        log(f"Error fetching Docker image metadata for {image_id}: {e}", "error")

    cache[image_id] = result
    return result


def _image_metadata(attrs, config, client, cache):
    """Identity of the image backing a container.

    ``image`` is the tag as written (Config.Image), so it survives an image
    being retagged; ``image_id`` is the resolved digest the container runs.
    Tags/digests are kept for back-compat and come from the (cached) image
    object.
    """
    image_id = attrs.get("Image")
    tags_digests = _image_tags_and_digests(client, image_id, cache)
    return {
        "image": config.get("Image") or image_id,
        "image_id": image_id,
        "image_tags": tags_digests["image_tags"],
        "image_repo_digests": tags_digests["image_repo_digests"],
    }


def _block_io(stats):
    """Cumulative (read, write) block-I/O bytes, or None when unavailable.

    Sums ``blkio_stats.io_service_bytes_recursive`` by op, case-insensitively:
    cgroup v1 reports "Read"/"Write", cgroup v2 reports "read"/"write". Returns
    None when the list is absent/empty so the server does not chart fake zero
    I/O on runtimes without blkio accounting.
    """
    entries = (stats.get("blkio_stats") or {}).get("io_service_bytes_recursive")
    if not entries:
        return None

    read = 0
    write = 0
    for item in entries:
        op = (item.get("op") or "").lower()
        value = item.get("value") or 0
        if op == "read":
            read += value
        elif op == "write":
            write += value
    return read, write


def _computed_stats(stats, prev):
    """The running-container stats block, computed against the prior sample."""
    data = {
        "cpu_percent": calculate_cpu_percent(stats, prev),
        "memory_percent": calculate_memory_percent(stats),
        "memory_usage": calculate_memory_usage(stats),
        "memory_limit": stats["memory_stats"].get("limit"),
        "pids_stats": stats.get("pids_stats", {}),
        "cpu_throttling": stats["cpu_stats"].get("throttling_data", {}),
        "online_cpus": stats["cpu_stats"].get("online_cpus"),
        "cpu_kernelmode_percent": _cpu_usage_percent(
            stats, prev, "usage_in_kernelmode"
        ),
        "cpu_usermode_percent": _cpu_usage_percent(stats, prev, "usage_in_usermode"),
    }

    block = _block_io(stats)
    if block is not None:
        data["block_read_bytes"], data["block_write_bytes"] = block

    # Networks key is not always defined.
    if stats.get("networks"):
        data["networks"] = stats["networks"]

    return data


def _merge_stats(entry, container):
    """Attach the stats block to a running container's entry when a prior sample
    exists, and record this sample for the next tick's delta."""
    stats = container.stats(stream=False, one_shot=True)
    prev = previous_stats.get(container.id)
    if prev is not None:
        entry.update(_computed_stats(stats, prev))
    previous_stats[container.id] = stats


def _build_entry(container, client, cache):
    """Build one container's payload entry from its full inspect attrs.

    The identity + state block is unconditional; stats are added only for a
    running container (and only when a prior sample exists, inside _merge_stats).
    """
    attrs = container.attrs or {}
    state = attrs.get("State") or {}
    config = attrs.get("Config") or {}
    status = state.get("Status")

    entry = {
        "name": _clean_name(attrs.get("Name")),
        **_image_metadata(attrs, config, client, cache),
        "status": status,
        "exit_code": state.get("ExitCode", 0),
        "oom_killed": state.get("OOMKilled", False),
        "restart_count": attrs.get("RestartCount", 0),
        "started_at": _normalize_timestamp(state.get("StartedAt")),
        "finished_at": _normalize_timestamp(state.get("FinishedAt")),
        "health": _health(state),
    }

    if status == "running":
        _merge_stats(entry, container)

    return entry


def _cap_containers(containers):
    """Cap the container list to _MAX_CONTAINERS, always keeping running
    containers first, then the newest non-running ones. Logs once per process
    when the cap actually bites."""
    global _cap_logged
    if len(containers) <= _MAX_CONTAINERS:
        return containers

    def created(container):
        return (container.attrs or {}).get("Created") or 0

    running = [c for c in containers if (c.attrs or {}).get("State") == "running"]
    others = sorted(
        (c for c in containers if (c.attrs or {}).get("State") != "running"),
        key=created,
        reverse=True,
    )
    capped = (running + others)[:_MAX_CONTAINERS]

    if not _cap_logged:
        log(
            f"Docker container count {len(containers)} exceeds cap "
            f"{_MAX_CONTAINERS}; collecting {len(capped)} "
            f"({len(running)} running prioritized)",
            "info",
        )
        _cap_logged = True

    return capped


def _prune_previous_stats(seen_ids):
    """Drop warm-up samples for containers not seen this tick (fixes the leak
    of removed containers, and restarts warm-up for recreated ids)."""
    for cid in list(previous_stats.keys()):
        if cid not in seen_ids:
            del previous_stats[cid]


def docker_containers(socket_url=None):
    """Collect every container's state (+ running stats).

    Returns a dict keyed by full container id on success ({} means genuinely
    zero containers), or None when the daemon is unreachable / the container
    listing fails -- the signal the server must never prune on.
    """
    client = get_docker_client(socket_url)
    if client is None:
        return None

    try:
        # One list call, sparse: doing the per-container inspect ourselves (via
        # reload()) isolates a NotFound race to that container instead of
        # raising out of the whole list, at the same API cost.
        containers = client.containers.list(all=True, sparse=True)
    except Exception as e:
        log(f"Error listing Docker containers: {e}", "error")
        # Rebuild the client next call: the daemon may have restarted or the
        # socket may have moved, and a fresh client re-runs endpoint resolution.
        invalidate_docker_client()
        return None

    containers = _cap_containers(containers)

    deadline = time.monotonic() + COLLECT_DEADLINE
    entries = {}
    seen_ids = set()
    image_cache = {}
    for container in containers:
        if time.monotonic() > deadline:
            # A partial map must never ship: the server prunes containers
            # missing from a dict payload, so a slow daemon would read as a
            # mass container removal. None is the never-prune failure signal.
            log(
                f"Docker collection exceeded {COLLECT_DEADLINE}s budget after "
                f"{len(entries)} of {len(containers)} containers; "
                "reporting collection failure",
                "error",
            )
            return None
        cid = container.id
        try:
            container.reload()
            if time.monotonic() > deadline:
                # Re-check between the reload and the (image inspect + stats)
                # secondary calls: each is CLIENT_TIMEOUT-bounded, so a
                # top-of-loop check alone could overshoot the budget by ~3
                # timeouts on a wedged daemon.
                log(
                    f"Docker collection exceeded {COLLECT_DEADLINE}s budget "
                    f"after {len(entries)} of {len(containers)} containers; "
                    "reporting collection failure",
                    "error",
                )
                return None
            entry = _build_entry(container, client, image_cache)
        except docker.errors.NotFound:
            log(f"Docker container {cid} vanished during collection, skipping", "debug")
            continue
        except requests.exceptions.RequestException as e:
            # Transport-level failure (read timeout on a wedged container, the
            # daemon dying mid-pass): the daemon side is sick, not this one
            # container. Skipping it would ship a PARTIAL map -- the server
            # prunes containers missing from a dict payload, so a live-but-
            # wedged container would read as removed and lose its alert state.
            # Same contract as the deadline bail above: None, never partial.
            # With the old 60s per-call default this path effectively never
            # fired (the call blocked into the watchdog instead); the tighter
            # CLIENT_TIMEOUT makes it reachable, so it must be honest.
            log(
                f"Docker transport error on container {cid}: {e}; "
                "reporting collection failure",
                "error",
            )
            invalidate_docker_client()
            return None
        except Exception as e:
            # Daemon answered but this one entry is unusable (malformed
            # payload, a daemon-side per-container error). Per-item isolation:
            # skip it, keep the rest.
            log(f"Error collecting Docker container {cid}: {e}", "error")
            continue
        entries[cid] = entry
        seen_ids.add(cid)

    _prune_previous_stats(seen_ids)
    return entries


def _cpu_usage_percent(stats, previous_stats, key):
    cpu_delta = stats["cpu_stats"]["cpu_usage"].get(key, 0) - previous_stats[
        "cpu_stats"
    ]["cpu_usage"].get(key, 0)
    system_delta = (
        stats["cpu_stats"]["system_cpu_usage"]
        - previous_stats["cpu_stats"]["system_cpu_usage"]
    )
    if system_delta > 0.0 and cpu_delta > 0.0:
        return (cpu_delta / system_delta) * 100.0
    return 0.0


def calculate_cpu_percent(stats, previous_stats):
    return _cpu_usage_percent(stats, previous_stats, "total_usage")


# From https://docs.docker.com/reference/cli/docker/container/stats/#description
# On Linux, the Docker CLI reports memory usage by subtracting cache usage from the total memory usage.
# The API does not perform such a calculation but rather provides the total memory usage and the amount
# from the cache so that clients can use the data as needed. The cache usage is defined as the value
# of total_inactive_file field in the memory.stat file on cgroup v1 hosts.
# On Docker 19.03 and older, the cache usage was defined as the value of cache field.
# On cgroup v2 hosts, the cache usage is defined as the value of inactive_file field.


def calculate_memory_percent(stats):
    if stats["memory_stats"]["stats"].get("total_inactive_file"):
        return (
            (
                stats["memory_stats"]["usage"]
                - stats["memory_stats"]["stats"]["total_inactive_file"]
            )
            / stats["memory_stats"]["limit"]
            * 100.0
        )
    if stats["memory_stats"]["stats"].get("inactive_file"):
        return (
            (
                stats["memory_stats"]["usage"]
                - stats["memory_stats"]["stats"]["inactive_file"]
            )
            / stats["memory_stats"]["limit"]
            * 100.0
        )
    return stats["memory_stats"]["usage"] / stats["memory_stats"]["limit"] * 100.0


def calculate_memory_usage(stats):
    if stats["memory_stats"]["stats"].get("total_inactive_file"):
        return (
            stats["memory_stats"]["usage"]
            - stats["memory_stats"]["stats"]["total_inactive_file"]
        )
    if stats["memory_stats"]["stats"].get("inactive_file"):
        return (
            stats["memory_stats"]["usage"]
            - stats["memory_stats"]["stats"]["inactive_file"]
        )
    return stats["memory_stats"]["usage"]


@debug("docker_metrics")
def docker_metrics(socket_url=None, **_kwargs):
    # Extra kwargs are accepted but ignored so a new server-side config key
    # nested under config["docker"] cannot make this raise TypeError on older
    # agents (collectors.py splats config["docker"] as **kwargs). Matches the
    # systemd.py / ceph.py precedent; docker.py was the odd one out. The image
    # inventory feature deliberately uses a TOP-LEVEL config key instead of
    # nesting here, but this guard closes the trap regardless.
    containers = docker_containers(socket_url)
    if containers is None:
        return None
    return {"containers": containers}
