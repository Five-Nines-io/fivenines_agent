"""Docker image OS-package inventory via the Docker archive API (image vuln
scanning, phase 1: Debian / Ubuntu / Alpine).

The only input the server is missing to scan a container image for OS-package
vulnerabilities is the package list *inside* the image, which only the agent can
produce. We get it WITHOUT running anything in the customer's container:
``GET /containers/{id}/archive?path=<p>`` (``container.get_archive`` in the SDK)
asks the daemon to tar a path from the container's on-demand-mounted layers and
stream it back -- what ``docker cp`` uses. So:

  * no binary is needed inside the image (dpkg-query / rpm / sh -- none),
  * it works on a stopped, and even never-started (``created``), container,
  * it is driver-agnostic, and a missing path is a clean 404,
  * nothing runs in the customer's container (unlike ``docker exec``),
  * under rootless / userns-remap the layer files on disk are owned by
    subordinate UIDs a host process cannot read at all -- the daemon runs
    *inside* that namespace, so the archive API is the ONLY viable design.

Because an image digest is immutable, extraction is once per image forever (not
per tick): the ImageInventoryCoordinator tracks done digests on disk. The heavy
work (N archive fetches + tar parsing + a POST) runs on the dedicated
ImageInventoryUploader thread, never on the collection loop (copying the
LogUploader / CaptureCoordinator split), so it can never stretch a tick toward
the systemd WatchdogSec.

Honesty contract (a security feature must never emit a false all-clear): an
extraction failure is NEVER an empty-and-clean payload. Every failure path
records a structured ``errors[]`` entry, so the server renders "not scannable,
<reason>" rather than "0 vulnerabilities". ``packages == []`` with
``errors == []`` is the one shape this module must never produce.
"""

import io
import os
import tarfile
import time
from threading import Lock

import docker

from fivenines_agent.debug import log
from fivenines_agent.docker import get_docker_client
from fivenines_agent.packages import get_packages_hash, parse_os_release
from fivenines_agent.queue_uploader import QueueUploader

# Paths inside the image. /etc/os-release is frequently a symlink to
# /usr/lib/os-release; the archive GET does NOT follow it (see _read_container_file).
OS_RELEASE_PATH = "/etc/os-release"
DPKG_STATUS_PATH = "/var/lib/dpkg/status"
APK_INSTALLED_PATH = "/lib/apk/db/installed"

# Per-file cap, enforced WHILE streaming (aborted mid-stream, not after) so a
# pathologically large DB cannot exhaust memory. Measured real DBs are tiny
# (postgres:16 dpkg status ~137 KB), so 5 MB is generous headroom.
MAX_FILE_BYTES = 5 * 1024 * 1024

# Hard cap on packages emitted per image. A 5 MB DB is well under this for real
# distros; if it ever bites we truncate AND record a package_cap error so the
# server never silently under-reports. Enforced DURING parsing (see
# _iter_stanzas), not as a post-hoc slice: a hostile image can pack ~580k
# minimal stanzas under the 5 MB file cap, and materializing them all before
# trimming is a ~145 MB allocation on an agent that shares the customer's box.
MAX_PACKAGES = 2000

# Max characters kept for a package name/version. Real ones are well under 100;
# anything longer is a corrupt or hostile DB, not data worth shipping.
MAX_FIELD_CHARS = 256

# Max digests honoured from one config["rescan_images"] directive. The server
# caps its own list at 3/tick, so this is only a guard against a malformed or
# hostile config: without it, a huge list would re-open the whole done set and
# turn the next ticks into a full-host re-extraction.
MAX_RESCAN_IMAGES = 10

# How many entries of an untrusted rescan_images list are even examined. The cap
# above bounds how many digests are HONOURED; this bounds how much work parsing
# costs, because apply_rescan_requests runs strip()/hash per entry on the
# watchdog-bounded collection loop. Without it a hostile/buggy server could send
# a million-entry list and force a million strip()+hash ops per tick. Same
# posture as MAX_FILE_BYTES/MAX_PACKAGES: bound the WORK, not just the result.
MAX_RESCAN_SCANNED = 100

# Even the immediate (attempts == 0) re-open case gets a per-digest floor: once a
# digest is re-opened at the server's request, a repeat request for it is ignored
# for this many seconds. A stale or looping rescan_images directive -- a server
# bug, or the last good config replayed by the Synchronizer during a /collect
# outage -- would otherwise re-extract a clean digest (archive fetch + tar parse
# + POST) on EVERY tick. The FIRST re-open is always immediate (no prior
# timestamp), so a legitimate re-inventory still runs on the same tick; only
# rapid repeats are throttled. Matches the "at most one extraction per hour" the
# retry ladder already gives the failure case (max_retry_seconds).
RESCAN_MIN_INTERVAL_SECONDS = 3600

# C0 + C1 control characters, deleted from every field that reaches the payload
# or a log line. str.translate mapping to None removes them; NUL is included
# (0x00), so this subsumes the original NUL-only scrub.
_CONTROL_CHARS = {c: None for c in list(range(0x20)) + [0x7F] + list(range(0x80, 0xA0))}

# Distro id -> package-DB family. Phase 1 covers dpkg + apk; RPM is phase 1.5
# (rpmdb.sqlite holds binary header blobs that need decoding) so it is reported
# unsupported, never silently empty.
_DPKG_IDS = {"debian", "ubuntu"}
_APK_IDS = {"alpine"}
_RPM_IDS = {
    "rhel",
    "almalinux",
    "rocky",
    "centos",
    "fedora",
    "amzn",
    "ol",
    "oracle",
    "sles",
    "sled",
}


class _ArchiveError(Exception):
    """A per-step archive read failure carrying the structured errors[] fields.

    ``type`` is the machine-readable reason the server keys on:
      not_found     -- 404 (missing file, or the container vanished mid-read)
      api_error     -- other daemon/SDK/stream error
      file_over_cap -- the tar stream exceeded MAX_FILE_BYTES
      parse_error   -- the tar carried no readable regular file (e.g. an
                       unresolved symlink chain)
    """

    def __init__(self, type_, message):
        super().__init__(message)
        self.type = type_
        self.message = message


def _scrub(value):
    """Strip control characters and the U+FFFD invalid-UTF-8 artifact, then bound
    the length.

    Package names/versions come verbatim out of a DB inside a customer image,
    which is attacker-controlled in the threat model. Removing only NUL is not
    enough: a newline, an ANSI escape, or a megabyte-long name would flow into
    the /image_packages payload, the dashboard, and the agent's own log lines.
    C0+C1 are dropped wholesale (none are legal in a package name) and the field
    is truncated to MAX_FIELD_CHARS."""
    cleaned = value.translate(_CONTROL_CHARS).replace("\ufffd", "")
    return cleaned[:MAX_FIELD_CHARS]


def _decode(raw):
    """Decode a DB blob as UTF-8, mapping invalid bytes to the replacement char
    (later stripped by _scrub on the fields we keep)."""
    return raw.decode("utf-8", errors="replace")


def _buffer_capped(bits):
    """Accumulate the archive byte-stream into a seekable buffer, aborting the
    moment it WOULD cross MAX_FILE_BYTES.

    The size check runs BEFORE the write, on a running total, so the buffer
    itself never exceeds the cap. (Checking buf.tell() after writing overshoots
    by up to one chunk -- docker-py streams 2 MiB chunks by default, i.e. ~40%
    over a cap whose whole job is to bound memory.)"""
    buf = io.BytesIO()
    total = 0
    try:
        for chunk in bits:
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise _ArchiveError(
                    "file_over_cap", f"archive exceeds {MAX_FILE_BYTES} bytes"
                )
            buf.write(chunk)
    except _ArchiveError:
        raise
    except Exception as e:
        # Deterministic message on the wire (the raw exception text varies by
        # daemon version and the server keys on errors[].type/message); the
        # detail goes to the debug log instead. Same rule as _get_archive.
        log(f"ImageInventory: stream read failed: {e}", "debug")
        raise _ArchiveError("api_error", "stream read failed")
    buf.seek(0)
    return buf


def _single_file_bytes(buf):
    """Return the bytes of the first regular file in the tar, or None when the
    tar holds no regular file (e.g. only a symlink entry -- the os-release
    gotcha before the linkTarget re-request).

    ``mode="r:"`` is deliberate: the default ``"r"`` means ``"r:*"``, which
    TRANSPARENTLY DECOMPRESSES. That would defeat _buffer_capped entirely, since
    the 5 MB cap is applied to the bytes on the wire -- a 46 KB xz-wrapped tar
    expands to 300 MB inside read(). The daemon always returns an uncompressed
    tar, so nothing legitimate is lost. The read is bounded for the same reason.
    (The member list stays bounded because _buffer_capped hard-caps the buffer at
    MAX_FILE_BYTES before the tar is opened.)"""
    try:
        with tarfile.open(fileobj=buf, mode="r:") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                data = extracted.read(MAX_FILE_BYTES + 1)
                if len(data) > MAX_FILE_BYTES:
                    raise _ArchiveError(
                        "file_over_cap", f"archive exceeds {MAX_FILE_BYTES} bytes"
                    )
                return data
        return None
    except _ArchiveError:
        raise
    except Exception as e:
        # A malformed/unreadable tar is an honest per-image verdict, not a
        # transient error: convert it so the caller records errors[] instead of
        # letting it escape and retry the digest forever.
        log(f"ImageInventory: unreadable tar archive: {e}", "debug")
        raise _ArchiveError("parse_error", "unreadable tar archive")


def _read_container_file(container, path):
    """Bytes of a single file at *path* inside *container*, following ONE symlink
    hop via the stat header's linkTarget.

    ``container.get_archive(path)`` returns ``(bits, stat)``. For /etc/os-release
    (a symlink to /usr/lib/os-release on Debian/Ubuntu) the GET returns a tar
    with a SYMLINK entry, not the file, and ``stat["linkTarget"]`` is the
    ABSOLUTE target -- re-request that (NOT the tar entry's relative linkname).
    An agent that skips this concludes every Debian image has no os-release and
    reports the whole fleet unscannable.

    Raises _ArchiveError on any failure so the caller records a structured
    errors[] entry (never a silent empty result)."""
    bits, stat = _get_archive(container, path)
    link = stat.get("linkTarget") if isinstance(stat, dict) else None
    if link:
        bits, _stat = _get_archive(container, link, symlink_of=path)
    content = _single_file_bytes(_buffer_capped(bits))
    if content is None:
        raise _ArchiveError("parse_error", f"no readable file in archive for {path}")
    return content


def _get_archive(container, path, symlink_of=None):
    """container.get_archive wrapper mapping SDK exceptions to _ArchiveError.

    NotFound (404) is the distroless/scratch signal for os-release and the
    "no package DB" signal for a DB path -- and also how a container removed
    mid-extraction surfaces; they are indistinguishable at the API, so we record
    the step where it happened and let the server label it.

    Messages are deterministic (they do NOT embed the SDK exception text, which
    varies by daemon version) so the errors[] payload is a stable cross-repo
    contract; the raw exception is logged at debug for diagnosis."""
    where = f"symlink target {path}" if symlink_of else path
    try:
        return container.get_archive(path)
    except docker.errors.NotFound as e:
        log(f"ImageInventory: {where} 404: {e}", "debug")
        raise _ArchiveError("not_found", f"{where} not found in image")
    except docker.errors.APIError as e:
        log(f"ImageInventory: {where} API error: {e}", "debug")
        raise _ArchiveError("api_error", f"{where}: daemon error")
    except Exception as e:
        # A non-docker failure (connection reset, requests error, ...). The SDK
        # never raises our internal _ArchiveError, so there is no re-raise guard.
        log(f"ImageInventory: {where} unexpected error: {e}", "debug")
        raise _ArchiveError("api_error", f"{where}: read error")


def _distro_family(distro):
    """'dpkg' | 'apk' | 'rpm' | None for a 'id:version' distro string."""
    distro_id = distro.split(":", 1)[0]
    if distro_id in _DPKG_IDS:
        return "dpkg"
    if distro_id in _APK_IDS:
        return "apk"
    if distro_id in _RPM_IDS or distro_id.startswith("opensuse"):
        return "rpm"
    return None


def _iter_stanzas(text):
    """Yield RFC822 stanzas (blank-line separated) lazily.

    Deliberately NOT ``text.split("\\n\\n")``: that materializes every stanza of
    the blob at once. Yielding lets a parser stop at its cap having built only
    that many entries, which is what keeps a hostile package DB from turning the
    5 MB file cap into a ~145 MB allocation."""
    start = 0
    length = len(text)
    while start < length:
        end = text.find("\n\n", start)
        if end == -1:
            yield text[start:]
            return
        yield text[start:end]
        start = end + 2


def _parse_dpkg_status(text, limit=None):
    """Installed packages from a dpkg /var/lib/dpkg/status blob.

    RFC822 stanzas split on blank lines. Keep Package + Version, but ONLY when
    Status contains 'install ok installed' -- otherwise a removed-but-config-
    files-remain entry ('deinstall ok config-files') is falsely reported as
    installed. Continuation lines (leading space/tab) are skipped.

    Returns (packages, truncated). Parsing stops one past *limit* so the caller
    can tell "exactly limit packages" from "more than limit"; the cap is read at
    call time (not as a default argument) so tests can patch MAX_PACKAGES."""
    if limit is None:
        limit = MAX_PACKAGES
    packages = []
    for stanza in _iter_stanzas(text):
        if not stanza.strip():
            continue
        name = version = status = None
        for line in stanza.split("\n"):
            if line[:1] in (" ", "\t"):
                continue  # folded continuation line
            if line.startswith("Package:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Status:"):
                status = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                version = line.split(":", 1)[1].strip()
        if name and version and status and "install ok installed" in status:
            entry = _package(name, version)
            if entry is not None:
                packages.append(entry)
                if len(packages) > limit:
                    return packages[:limit], True
    return packages, False


def _parse_apk_installed(text, limit=None):
    """Installed packages from an apk /lib/apk/db/installed blob. Same stanza
    shape as dpkg; keys P: (package) and V: (version). The apk installed DB only
    lists installed packages, so no status filter is needed.

    Returns (packages, truncated), capped during parsing like _parse_dpkg_status."""
    if limit is None:
        limit = MAX_PACKAGES
    packages = []
    for stanza in _iter_stanzas(text):
        if not stanza.strip():
            continue
        name = version = None
        for line in stanza.split("\n"):
            if line.startswith("P:"):
                name = line[2:].strip()
            elif line.startswith("V:"):
                version = line[2:].strip()
        if name and version:
            entry = _package(name, version)
            if entry is not None:
                packages.append(entry)
                if len(packages) > limit:
                    return packages[:limit], True
    return packages, False


def _package(name, version):
    """One package entry, or None when a field is unusable after scrubbing.

    ``ecosystem: null`` means "the image's OS ecosystem"; it is present now so a
    later phase can send npm/pypi/etc. entries on the same endpoint without a
    contract break -- two characters now, no v2 endpoint later.

    The emptiness check runs AFTER scrubbing, which matters: a name of "\\x00" is
    truthy raw but scrubs to "". Emitting it would ship a nameless package AND
    make ``packages`` non-empty, which suppresses the never-empty-and-clean
    guard in _build_payload -- a false all-clear on a security feature. Dropping
    the entry keeps that guard armed (if every entry drops, it fires)."""
    clean_name = _scrub(name)
    clean_version = _scrub(version)
    if not clean_name or not clean_version:
        return None
    return {"name": clean_name, "version": clean_version, "ecosystem": None}


def _payload(image_id, distro, packages, errors):
    """Assemble the /image_packages POST body. packages_hash reuses the host
    path's get_packages_hash (byte-compatible dedupe) and is null when there are
    no packages (a failure payload), so the hash always identifies a real set."""
    return {
        "image_id": image_id,
        "distro": distro,
        "packages_hash": get_packages_hash(packages) if packages else None,
        "packages": packages,
        "errors": errors,
    }


def _build_payload(container, image_id):
    """Extract one image's OS package list into the /image_packages payload.

    Always returns a dict with all five keys; a failure records a structured
    errors[] entry and empty packages (never empty-and-clean)."""
    errors = []

    # 1. os-release -> distro (following the /etc/os-release symlink).
    try:
        os_release_bytes = _read_container_file(container, OS_RELEASE_PATH)
    except _ArchiveError as e:
        # No os-release (distroless/scratch) or the container vanished: unsupported.
        errors.append({"step": "os_release", "type": e.type, "message": e.message})
        return _payload(image_id, None, [], errors)

    distro = parse_os_release(_decode(os_release_bytes).splitlines())
    if distro == "unknown":
        errors.append(
            {
                "step": "os_release",
                "type": "unsupported_distro",
                "message": "os-release has no ID field",
            }
        )
        return _payload(image_id, None, [], errors)

    # 2. Branch on the distro family.
    family = _distro_family(distro)
    if family == "rpm":
        errors.append(
            {
                "step": "distro",
                "type": "unsupported_distro",
                "message": f"RPM-based distro {distro!r}; extraction is phase 1.5",
            }
        )
        return _payload(image_id, distro, [], errors)
    if family is None:
        errors.append(
            {
                "step": "distro",
                "type": "unsupported_distro",
                "message": f"unsupported distro {distro!r}",
            }
        )
        return _payload(image_id, distro, [], errors)

    # 3. Read + parse the package DB.
    if family == "dpkg":
        db_path, step, parser = DPKG_STATUS_PATH, "dpkg_status", _parse_dpkg_status
    else:
        db_path, step, parser = (
            APK_INSTALLED_PATH,
            "apk_installed",
            _parse_apk_installed,
        )

    try:
        db_bytes = _read_container_file(container, db_path)
    except _ArchiveError as e:
        errors.append({"step": step, "type": e.type, "message": e.message})
        return _payload(image_id, distro, [], errors)

    # The parser caps itself, so an oversized DB never materializes in full.
    # Truncation keeps the first MAX_PACKAGES entries in FILE order and the
    # result is sorted by name afterwards -- the sort is what the wire contract
    # pins (packages_hash is order-sensitive), so it must survive truncation.
    parsed, truncated = parser(_decode(db_bytes))
    packages = sorted(parsed, key=lambda p: p["name"])
    if truncated:
        errors.append(
            {
                "step": step,
                "type": "package_cap",
                "message": f"package list truncated to {MAX_PACKAGES}",
            }
        )
    if not packages:
        # A DB we could read but parsed nothing is a parse failure, not a clean
        # zero (which the server would render as "0 vulnerabilities").
        errors.append(
            {
                "step": step,
                "type": "parse_error",
                "message": "no installed packages parsed from package DB",
            }
        )
    return _payload(image_id, distro, packages, errors)


def build_image_inventory(job):
    """Worker build_fn: extract the OS package list for one image digest.

    Returns the /image_packages payload dict, or None to SKIP (retry later) when
    we cannot even reach the daemon or the representative container is already
    gone -- a transient infra condition, not an image verdict. A container that
    disappears *mid-extraction* instead surfaces as a not_found error inside a
    real payload (see _build_payload)."""
    image_id = job["image_id"]
    container_id = job["container_id"]
    socket_url = job.get("socket_url")

    client = get_docker_client(socket_url)
    if client is None:
        log(f"ImageInventory: daemon unreachable for {image_id}, will retry", "debug")
        return None

    try:
        container = client.containers.get(container_id)
    except docker.errors.NotFound:
        # The container we picked as this digest's reader vanished before we
        # started. Retry: a later tick re-picks the digest with whatever
        # container then runs it (and if none does, we never learn the digest
        # again anyway, which is fine -- an image with no container is out of scope).
        log(
            f"ImageInventory: container {container_id} gone before extraction, "
            f"retrying {image_id} later",
            "debug",
        )
        return None
    except Exception as e:
        log(f"ImageInventory: cannot load container {container_id}: {e}", "error")
        return None

    return _build_payload(container, image_id)


class ImageInventoryCoordinator:
    """Tracks which image digests have been inventoried, so each is extracted
    exactly once (digests are immutable -- once done, done forever).

    Mirrors CaptureCoordinator, but keyed by image_id and NOT driven by a backend
    command: the trigger is "this digest was seen running on the host". done ids
    are persisted to disk (newline-delimited) so a Restart=always agent does not
    re-extract the whole host on every restart; the set is bounded (FIFO evict)
    so it cannot grow without limit -- an evicted-then-reseen image is simply
    re-scanned, which is harmless. in_flight guards against re-selecting a digest
    whose extraction is still queued/running. mark_done advances the done set
    ONLY on a confirmed 200 (any definitive verdict, including a refusal);
    mark_failed releases the slot so a transient failure retries.

    Retries are bounded. mark_failed alone would re-offer a failing digest every
    single tick forever, and because the uploader runs build_fn before send_fn,
    each attempt re-runs the FULL extraction even when only the POST is failing
    -- so a backend outage or a permanently-rejected image becomes a treadmill
    (3 digests/tick, each re-fetching archives and re-parsing tars). Instead each
    failure schedules the next attempt with exponential backoff, and after
    max_attempts the digest is given up on. The give-up set is deliberately
    IN-MEMORY, not persisted: a multi-hour outage must not permanently blind an
    image, so a restart re-tries it."""

    def __init__(
        self,
        state_path,
        max_done=5000,
        max_per_tick=3,
        max_attempts=5,
        retry_base_seconds=60,
        max_retry_seconds=3600,
        rescan_min_interval_seconds=RESCAN_MIN_INTERVAL_SECONDS,
        now_fn=time.time,
    ):
        self.state_path = state_path
        self._max_done = max_done
        self._max_per_tick = max_per_tick
        self._max_attempts = max_attempts
        self._retry_base_seconds = retry_base_seconds
        self._max_retry_seconds = max_retry_seconds
        self._rescan_min_interval = rescan_min_interval_seconds
        self._now = now_fn
        self._lock = Lock()
        # Serializes _persist across its two writer threads (mark_done on the
        # uploader, reset on the collection loop) so their temp-write+rename
        # cannot interleave. Distinct from _lock, which guards in-memory state.
        self._persist_lock = Lock()
        self._done = self._load()  # list, insertion order (for FIFO eviction)
        self._done_set = set(self._done)
        self._in_flight = set()
        # image_id -> consecutive failed attempts, and the epoch before which the
        # digest must not be re-selected. Cleared on success.
        self._attempts = {}
        self._next_retry = {}
        # Digests that exhausted max_attempts this process. In-memory on purpose.
        self._gave_up = set()
        # image_id -> epoch of the last rescan-driven re-open, so a repeated
        # directive cannot re-extract the same digest every tick (see reset()).
        self._last_reopen = {}

    def _load(self):
        try:
            with open(self.state_path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []
        except Exception as e:
            log(
                f"ImageInventoryCoordinator: cannot read {self.state_path}: {e}",
                "error",
            )
            return []

    def _persist(self):
        """Serialize the done set to disk, atomically.

        reset() (collection loop) and mark_done()/eviction (uploader thread) are
        BOTH writers now, which introduces two hazards this closes:
          - lost update: each caller used to snapshot _done and write it after
            releasing the lock, so an older snapshot could land after a newer one
            -- silently dropping a just-done digest, or resurrecting a re-opened
            one, on the next restart. Re-read the authoritative _done under _lock
            HERE instead of trusting a caller's stale snapshot; whoever writes
            last writes the latest state.
          - torn file: a crash between truncate and write left a partial file.
            Write a sibling temp file and os.replace() it onto state_path (atomic
            on POSIX), so a failed write can never truncate the real file.
        _persist_lock serializes the two threads' write+rename. _lock is held
        only for the list() copy, never across the disk write -- select_jobs runs
        on the collection loop and must not stall on uploader-thread I/O."""
        with self._persist_lock:
            with self._lock:
                done = list(self._done)
            tmp_path = self.state_path + ".tmp"
            try:
                with open(tmp_path, "w") as f:
                    f.write("\n".join(done))
                os.replace(tmp_path, self.state_path)
            except Exception as e:
                # Best-effort: a write failure must not break extraction. The
                # in-memory done set still prevents re-extraction within this
                # process. The real file is untouched (only the temp was written).
                log(
                    f"ImageInventoryCoordinator: cannot persist "
                    f"{self.state_path}: {e}",
                    "error",
                )

    def select_jobs(self, image_container_map, socket_url):
        """Up to max_per_tick extraction jobs for digests neither done nor in
        flight, marking each in-flight. *image_container_map* is
        {image_id: container_id} for the digests seen running this tick."""
        jobs = []
        now = self._now()
        with self._lock:
            for image_id, container_id in image_container_map.items():
                if len(jobs) >= self._max_per_tick:
                    break
                if (
                    not image_id
                    or image_id in self._done_set
                    or image_id in self._in_flight
                    or image_id in self._gave_up
                ):
                    continue
                if now < self._next_retry.get(image_id, 0):
                    continue  # still backing off from a previous failure
                self._in_flight.add(image_id)
                jobs.append(
                    {
                        "image_id": image_id,
                        "container_id": container_id,
                        "socket_url": socket_url,
                    }
                )
        return jobs

    def mark_done(self, image_id):
        """Uploader callback on a confirmed 200: record the digest as done (no
        re-extraction, survives restart) and free the in-flight slot."""
        if not image_id:
            return
        with self._lock:
            self._in_flight.discard(image_id)
            # A definitive verdict clears the failure history.
            self._attempts.pop(image_id, None)
            self._next_retry.pop(image_id, None)
            if image_id in self._done_set:
                return
            self._done.append(image_id)
            self._done_set.add(image_id)
            while len(self._done) > self._max_done:
                evicted = self._done.pop(0)
                self._done_set.discard(evicted)
        # Persist OUTSIDE the lock. select_jobs takes this same lock on the
        # collection loop, so holding it across a disk write (up to max_done
        # digests, ~360 KB) would let uploader-thread I/O stall a tick -- the one
        # path where this subsystem could reach the thing it exists to stay off.
        # _persist re-reads _done under the lock, so dropping the snapshot here
        # does not race an interleaving reset() on the collection loop.
        self._persist()

    def release(self, image_id):
        """Free the in-flight slot WITHOUT recording an attempt.

        For backpressure, not failure: when select_and_enqueue sheds a job
        because the queue is full, the extraction never ran. Counting that as a
        failed attempt would let a busy queue exhaust max_attempts and give up on
        a digest that was never actually tried."""
        if not image_id:
            return
        with self._lock:
            self._in_flight.discard(image_id)

    def reset(self, image_ids):
        """Re-open digests the server asked to re-inventory (server issue #676).

        A transient api_error still ends in a 200 -- the failure is reported IN
        the payload, not by the status code -- so mark_done recorded the digest
        as done forever and the image read "not scannable" for good. Digests are
        immutable, so nothing on this side can ever re-offer it.
        config["rescan_images"] is the server un-sticking exactly those: it lists
        only api_error digests THIS host runs, past a 6h backoff.

        Drops each digest from done and from gave_up so select_jobs offers it
        again, and NEVER clears _attempts.

        Two floors keep a stale or looping directive from re-extracting the same
        digest every tick (a full archive fetch + tar parse + POST):
          - a digest with a failure history is re-armed onto the retry ladder
            (_retry_delay) rather than made immediately eligible, so one that had
            exhausted max_attempts cannot be un-given-up, retried, and give up
            again on EVERY tick -- the delay climbs to the cap, ~one extraction
            per hour.
          - EVERY re-open, including the immediate attempts == 0 case, stamps
            _last_reopen and is skipped if it was re-opened within
            rescan_min_interval. The main #676 case (api_error reported inside a
            200) clears the failure history, so attempts is 0 and the ladder does
            not apply; without this second floor a directive the server keeps
            re-sending -- a bug, or the last config replayed by the Synchronizer
            during a /collect outage, when the server never learns to stop --
            would re-extract that clean digest on every tick.
        The FIRST re-open of a digest is always immediate: it has no prior
        _last_reopen, so a legitimate re-inventory still runs on the same tick;
        only rapid repeats are throttled.

        An in-flight digest is skipped: select_jobs would skip it anyway, and
        clearing it would let the same extraction be enqueued twice. A digest
        that is neither done nor given up has nothing to un-stick, so it is
        skipped too (the normal selection path already owns it, backoff
        included).

        Returns the digests actually re-opened, for the caller to log."""
        if not image_ids:
            return []
        reopened = []
        now = self._now()
        with self._lock:
            removed_done = set()
            for image_id in image_ids:
                if not image_id or image_id in self._in_flight:
                    continue
                was_done = image_id in self._done_set
                was_gave_up = image_id in self._gave_up
                if not (was_done or was_gave_up):
                    continue
                # Anti-treadmill floor: skip a digest re-opened too recently, so a
                # directive the server keeps re-sending cannot re-extract it every
                # tick. The first re-open (no prior timestamp) always passes.
                last_reopen = self._last_reopen.get(image_id)
                if (
                    last_reopen is not None
                    and now - last_reopen < self._rescan_min_interval
                ):
                    continue
                self._last_reopen[image_id] = now
                self._gave_up.discard(image_id)
                # Re-arm onto the retry ladder when this digest has already
                # failed, so a re-open cannot bypass the backoff (see docstring).
                attempts = self._attempts.get(image_id, 0)
                if attempts:
                    self._next_retry[image_id] = now + self._retry_delay(attempts)
                if was_done:
                    self._done_set.discard(image_id)
                    removed_done.add(image_id)
                reopened.append(image_id)
            if removed_done:
                # One pass rather than list.remove() per digest: _done holds up to
                # max_done entries and this runs on the collection loop.
                self._done = [d for d in self._done if d not in removed_done]
        # Persist outside the lock, for the reason spelled out in mark_done.
        # Without persisting, a restart reloads the digest as done and the
        # server's directive is silently lost. Only a done removal touches the
        # file; a gave-up-only re-open is in-memory, so it pays no disk write.
        if removed_done:
            self._persist()
        return reopened

    def mark_failed(self, image_id):
        """Uploader callback on a transient failure (no payload, non-200, or
        exception): free the in-flight slot and schedule the next attempt with
        exponential backoff. done is NOT advanced.

        After max_attempts consecutive failures the digest is given up on for
        this process, so a permanently-failing image cannot occupy a per-tick
        slot forever (which would starve digests that CAN be scanned)."""
        if not image_id:
            return
        with self._lock:
            self._in_flight.discard(image_id)
            attempts = self._attempts.get(image_id, 0) + 1
            self._attempts[image_id] = attempts
            if attempts >= self._max_attempts:
                self._gave_up.add(image_id)
                self._next_retry.pop(image_id, None)
                log(
                    f"ImageInventoryCoordinator: giving up on {image_id} after "
                    f"{attempts} failed attempts (retries resume on restart)",
                    "error",
                )
                return
            self._next_retry[image_id] = self._now() + self._retry_delay(attempts)

    def _retry_delay(self, attempts):
        """Exponential backoff for the Nth consecutive failure, capped. Shared
        with reset() so a server-driven re-open lands on the SAME ladder as an
        ordinary retry instead of inventing a second cadence."""
        return min(
            self._retry_base_seconds * (2 ** (attempts - 1)),
            self._max_retry_seconds,
        )


def apply_rescan_requests(coordinator, config):
    """Glue: honour the server's TOP-LEVEL config["rescan_images"] directive.

    Must run BEFORE select_and_enqueue on the same tick, so a re-opened digest is
    offered immediately instead of waiting for the next one.

    The value is untrusted input off the wire: anything that is not a list of
    non-empty strings is ignored rather than raising. Two independent caps keep a
    malformed or hostile config cheap on the watchdog-bounded collection loop:
    only the first MAX_RESCAN_SCANNED entries are examined (bounding the parse
    work) and at most MAX_RESCAN_IMAGES distinct digests are honoured (bounding
    the re-opens); an over-long entry is dropped before strip() copies it. A
    digest not among this host's currently-running containers is left untouched
    by reset() (it only re-opens digests it already tracks), and select_jobs
    offers only what data["docker"]["containers"] reported this tick.

    A free function so it is testable without an Agent, mirroring
    log_capture.evaluate_and_enqueue.

    Returns the digests actually re-opened."""
    requested = config.get("rescan_images") if isinstance(config, dict) else None
    if not isinstance(requested, (list, tuple)):
        return []

    digests = []
    seen = set()
    # Slice the input so a huge list cannot force O(n) strip()/hash on the loop;
    # reject an over-long entry BEFORE strip() (len() is O(1)) so a multi-MB
    # string cannot allocate a copy here. See MAX_RESCAN_SCANNED.
    for entry in requested[:MAX_RESCAN_SCANNED]:
        if not isinstance(entry, str) or len(entry) > MAX_FIELD_CHARS:
            continue
        digest = entry.strip()
        if not digest or digest in seen:
            continue
        seen.add(digest)
        digests.append(digest)
        if len(digests) >= MAX_RESCAN_IMAGES:
            break

    if not digests:
        return []

    reopened = coordinator.reset(digests)
    if reopened:
        log(
            f"ImageInventory: re-opening {len(reopened)} image(s) at the "
            f"server's request: {', '.join(reopened)}",
            "info",
        )
    return reopened


def select_and_enqueue(coordinator, queue, image_container_map, socket_url):
    """Glue: select up to max_per_tick jobs and enqueue them. Returns the jobs
    actually enqueued. A free function so it is testable without an Agent.

    The bounded queue drops the OLDEST job on overflow, and a dropped job never
    reaches the uploader -> its in-flight slot would leak forever. So when the
    queue is full, shed the NEW job and release its slot (it retries next tick)
    rather than evict an already-queued one. release() rather than mark_failed():
    the extraction never ran, so this is backpressure, not a failed attempt."""
    jobs = coordinator.select_jobs(image_container_map, socket_url)
    enqueued = []
    for job in jobs:
        if queue.full():
            log("ImageInventory: queue full, shedding extraction job", "error")
            coordinator.release(job["image_id"])
            continue
        queue.put(job)
        enqueued.append(job)
    return enqueued


class ImageInventoryUploader(QueueUploader):
    """Extracts + uploads one image's OS package inventory off the collection
    loop. build_fn(job) fetches the package DB via the archive API and returns
    the /image_packages payload (or None to skip -> retry); send_fn(payload)
    POSTs it and returns truthy on a 200 (any definitive verdict, including a
    refusal). The drain / per-job isolation / shutdown loop is shared with
    LogUploader via QueueUploader."""

    label = "ImageInventoryUploader"
    job_id_key = "image_id"
    payload_noun = "inventory"
