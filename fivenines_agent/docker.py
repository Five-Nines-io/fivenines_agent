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

import docker

from fivenines_agent.debug import debug, log

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


def get_docker_client(socket_url=None):
    try:
        if socket_url:
            return docker.DockerClient(base_url=socket_url)
        else:
            return docker.from_env()
    except docker.errors.DockerException as e:
        log(f"Error connecting to Docker daemon: {e}", "error")
        return None


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
        return None

    containers = _cap_containers(containers)

    entries = {}
    seen_ids = set()
    image_cache = {}
    for container in containers:
        cid = container.id
        try:
            container.reload()
            entry = _build_entry(container, client, image_cache)
        except docker.errors.NotFound:
            log(f"Docker container {cid} vanished during collection, skipping", "debug")
            continue
        except Exception as e:
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
def docker_metrics(socket_url=None):
    containers = docker_containers(socket_url)
    if containers is None:
        return None
    return {"containers": containers}
