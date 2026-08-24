"""Ubuntu Pro attachment + enabled-services collector (server #746).

The vulnerability scanner files a CVE whose only patch is published under an
`Ubuntu:Pro:*` OSV ecosystem in a separate "fixable only with a subscription"
bucket rather than in the work queue. That is exact for an UNATTACHED host and
merely pessimistic for an ATTACHED one, which can `apt install` the ESM fix
today. The server cannot tell the two apart on its own; this collector is that
signal.

Contract rules (contract fixture: tests/fixtures/ubuntu_pro_contract_payload.json):

1. ATTACHMENT ALONE IS NOT ENOUGH. A machine can be attached with every service
   disabled (`pro disable esm-infra` is one command), and each Ubuntu Pro OSV
   ecosystem maps to the archive pocket ONE SPECIFIC SERVICE opens -- esm-infra
   does not unlock a FIPS-only fix. The server matches the service list against
   its pocket table, so it needs the list, not a boolean.

2. ``None`` MEANS "COULD NOT DETERMINE", AND ONLY THAT. The server preserves the
   stored columns on null and never writes ``false`` from one. A timed-out `pro`
   is not evidence a machine detached, and reporting it as one would bounce that
   host's ESM findings between the work queue and the subscription bucket on
   every hiccup -- each flip a findings rewrite and a rescan. So every ambiguous
   outcome here resolves to ``None``, NEVER to ``{"attached": False}``.

3. THE SERVICE NAMES TRAVEL VERBATIM (lowercased). There is deliberately no
   allowlist: the server ignores tokens it does not recognise, which is exactly
   what keeps a service Canonical adds next year from needing an agent release.

4. CACHED. This rides /collect, which runs every 15-60s, and the value changes
   about once in a machine's lifetime. Shelling out per tick is not acceptable;
   the reading is recomputed at most once per _CACHE_TTL and the server reads
   the stored columns at scan time, so minutes of staleness cost nothing.

Non-Ubuntu hosts have no `pro` and no status cache, so they report ``None`` --
never ``{"attached": False}``, which would claim a Debian box was checked and
found detached.
"""

import json
import shutil
import subprocess

from fivenines_agent.cache import TTLCache
from fivenines_agent.debug import debug, log
from fivenines_agent.subprocess_utils import get_clean_env

# Hard per-call subprocess timeout (seconds). `pro api` on these two endpoints
# does no network I/O (both are documented "network access required: no"); the
# ceiling only keeps a wedged client out of the watchdog-bounded collect tick.
# Worst case is two calls, and only on an ATTACHED host -- a detached one
# answers in a single call (see _read_from_pro_api).
_SUBPROCESS_TIMEOUT = 10

# How long one reading is reused. Deliberately long: attachment changes about
# once in a machine's lifetime, and the server reads the stored columns at scan
# time rather than off the tick. FAILURES ARE CACHED TOO -- a `pro` that hangs
# for the full timeout must not be re-run on the next tick 15 seconds later.
_CACHE_TTL = 900
_CACHE_KEY = "ubuntu_pro"

# The two `pro api` endpoints. Both return the standard envelope:
# {"_schema_version": .., "data": {"attributes": {..}, ..}, "result": "success",
#  "errors": [], "warnings": [], "version": ".."}
_IS_ATTACHED_ENDPOINT = "u.pro.status.is_attached.v1"
_ENABLED_SERVICES_ENDPOINT = "u.pro.status.enabled_services.v1"

# Fallback source: the on-disk status cache `pro` itself maintains. Plain file,
# world-readable, no subprocess and no network. See _read_from_status_cache.
_STATUS_CACHE_FILE = "/var/lib/ubuntu-advantage/status.json"

# Cap on how much of the status cache is read. A real one is tens of KiB.
_MAX_STATUS_CHARS = 4 * 1024 * 1024

# The service-entry status that means "this pocket is actually open". `pro`
# also emits "disabled", "n/a" and "warning"; none of those open a pocket.
_ENABLED_STATUS = "enabled"

# Mirrors the server's UBUNTU_PRO_MAX_SERVICES / _MAX_SERVICE_LENGTH so the two
# sides agree on what a sane list looks like. Real hosts report under fifteen
# services with names under twenty characters; these only bound a pathological
# reading, they are not a filter (rule 3: no allowlist).
_MAX_SERVICES = 32
_MAX_SERVICE_CHARS = 64

_cache = TTLCache()


def _pro_api_attributes(binary, endpoint):
    """Return the `data.attributes` object of a `pro api <endpoint>` call, or None.

    Unlike the WireGuard collector, output on stderr is NOT a failure here. `pro`
    warns on stderr about things that do not affect the answer (an unwritable
    cache when running unprivileged, an APT news notice) while still printing a
    complete envelope on stdout. The authority is the envelope's own `result`
    field plus the exit code, which `pro api` sets to 1 for anything that is not
    a successful call.
    """
    try:
        result = subprocess.run(
            [binary, "api", endpoint],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=_SUBPROCESS_TIMEOUT,
            env=get_clean_env(),
        )
    except (OSError, subprocess.SubprocessError) as e:
        log(f"Ubuntu Pro: `pro api {endpoint}` failed: {e}", "debug")
        return None

    if result.returncode != 0:
        # The realistic trigger is an endpoint an older ubuntu-advantage-tools
        # does not implement, which is why this is debug and not error: the
        # status-cache fallback answers those hosts.
        log(
            f"Ubuntu Pro: `pro api {endpoint}` exited {result.returncode}: "
            f"{(result.stderr or '').strip() or 'no error output'}",
            "debug",
        )
        return None

    try:
        payload = json.loads(result.stdout or "")
    except ValueError as e:
        log(f"Ubuntu Pro: could not parse `pro api {endpoint}`: {e}", "debug")
        return None

    if not isinstance(payload, dict):
        log(f"Ubuntu Pro: `pro api {endpoint}` was not an object", "debug")
        return None

    # `result` defaults to "success" and is absent from no released envelope,
    # but tolerate its absence rather than blanking a future shape that only
    # dropped a redundant field.
    outcome = payload.get("result")
    if outcome is not None and outcome != "success":
        log(f"Ubuntu Pro: `pro api {endpoint}` reported result={outcome!r}", "debug")
        return None

    data = payload.get("data")
    attributes = data.get("attributes") if isinstance(data, dict) else None
    if not isinstance(attributes, dict):
        log(f"Ubuntu Pro: `pro api {endpoint}` carried no attributes", "debug")
        return None
    return attributes


def _service_names(raw):
    """Normalize an enabled-services array into a sorted name list, or None.

    Two entry shapes are real and both are accepted: current clients emit
    ``{"name": "esm-infra", "variant_enabled": .., "variant_name": ..}`` while
    older ones emit the plain string. The variant is deliberately ignored --
    `realtime-kernel` opens the same pocket whichever variant is enabled, and
    the server keys on the service name.

    An entry whose name cannot be read fails the WHOLE list rather than being
    skipped. A silently short list is a wrong answer in the shape the server
    cannot detect: it would read as "that pocket is closed" and keep an
    installable fix filed as unfixable, with nothing anywhere saying why.

    Sorted and deduped so the payload is stable across `pro` versions and the
    server's "did the entitlement actually change" comparison never fires on a
    reordering.
    """
    if not isinstance(raw, list):
        log(
            f"Ubuntu Pro: enabled services were {type(raw).__name__}, not a list",
            "error",
        )
        return None

    names = set()
    for entry in raw:
        name = entry.get("name") if isinstance(entry, dict) else entry
        if not isinstance(name, str):
            log(
                f"Ubuntu Pro: unreadable service entry {entry!r}; "
                "reporting null rather than a short list",
                "error",
            )
            return None
        name = name.strip().lower()[:_MAX_SERVICE_CHARS]
        if name:
            names.add(name)

    ordered = sorted(names)
    if len(ordered) > _MAX_SERVICES:
        log(
            f"Ubuntu Pro: {len(ordered)} enabled services reported, "
            f"capping at {_MAX_SERVICES}",
            "error",
        )
    return ordered[:_MAX_SERVICES]


def _read_from_pro_api(binary):
    """Reading from the `pro api` endpoints, or None if either half is missing."""
    attributes = _pro_api_attributes(binary, _IS_ATTACHED_ENDPOINT)
    if attributes is None:
        return None

    attached = attributes.get("is_attached")
    if attached is not True and attached is not False:
        log(
            f"Ubuntu Pro: is_attached was {attached!r}, not a boolean",
            "error",
        )
        return None

    if not attached:
        # No second call: `_enabled_services` itself returns an empty list the
        # moment it sees an unattached machine, so skipping the spawn is exactly
        # equivalent -- and it keeps the common case (every non-Pro Ubuntu host
        # in the fleet) at one subprocess per cache window.
        return {"attached": False, "services": []}

    attributes = _pro_api_attributes(binary, _ENABLED_SERVICES_ENDPOINT)
    if attributes is None:
        # BOTH HALVES OR NOTHING. `{"attached": true, "services": []}` is a real,
        # meaningful state ("attached, every service disabled") and sending it
        # because the service list could not be READ would tell the server we
        # checked and found no open pocket. That is the pessimistic direction,
        # so nothing breaks loudly -- a Pro customer's fixes just stay filed as
        # unfixable forever with no signal anywhere. null preserves instead.
        return None

    services = _service_names(attributes.get("enabled_services"))
    if services is None:
        return None
    return {"attached": True, "services": services}


def _read_from_status_cache():
    """Reading from /var/lib/ubuntu-advantage/status.json, or None.

    The fallback for the hosts the `pro api` path cannot answer: an
    ubuntu-advantage-tools too old to implement the endpoints, or a `pro` that
    is installed but not on the agent's PATH. It is a world-readable file that
    `pro` refreshes on every status run, on attach/detach and on its own timer,
    so it is minutes-to-hours stale at worst against a value that changes about
    once in a machine's lifetime -- strictly more useful than the null it
    replaces.

    Same schema as `pro status --format json`: a top-level `attached` boolean
    and a `services` array whose entries carry a name and a status.
    """
    try:
        with open(_STATUS_CACHE_FILE, "r", errors="replace") as handle:
            raw = handle.read(_MAX_STATUS_CHARS)
    except (OSError, ValueError):
        # ValueError covers open()'s embedded-null-byte rejection. Absent is the
        # normal case on every non-Ubuntu host, so this is not worth a log line.
        return None

    try:
        payload = json.loads(raw)
    except ValueError as e:
        log(f"Ubuntu Pro: could not parse {_STATUS_CACHE_FILE}: {e}", "error")
        return None

    if not isinstance(payload, dict):
        log(f"Ubuntu Pro: {_STATUS_CACHE_FILE} was not an object", "error")
        return None

    attached = payload.get("attached")
    if attached is not True and attached is not False:
        log(
            f"Ubuntu Pro: status cache attached was {attached!r}, not a boolean",
            "error",
        )
        return None

    if not attached:
        return {"attached": False, "services": []}

    services = payload.get("services")
    if not isinstance(services, list):
        log(
            f"Ubuntu Pro: status cache services were {type(services).__name__}, "
            "not a list",
            "error",
        )
        return None

    names = []
    for entry in services:
        if not isinstance(entry, dict):
            log(
                f"Ubuntu Pro: status cache service entry {entry!r} is not an object",
                "error",
            )
            return None
        # ONLY "enabled". An entitled-but-disabled service opens no pocket, and
        # neither does one in "warning" -- the pessimistic reading is the safe
        # one here, since over-reporting would move a genuinely unfixable
        # finding into the work queue.
        if entry.get("status") == _ENABLED_STATUS:
            names.append(entry.get("name"))

    normalized = _service_names(names)
    if normalized is None:
        return None
    return {"attached": True, "services": normalized}


def _read():
    """Best available reading of this host's entitlement, or None.

    `pro api` first (authoritative and always current), the on-disk status cache
    second. Note that the fallback also covers a `pro` that TIMED OUT, not just
    one that is absent or too old: a slightly stale reading of a value that
    changes once in a machine's lifetime beats a null that teaches the server
    nothing.
    """
    binary = shutil.which("pro")
    reading = _read_from_pro_api(binary) if binary else None
    if reading is None:
        reading = _read_from_status_cache()
    if reading is not None:
        return reading

    if binary is None:
        # The overwhelmingly common case: not an Ubuntu host at all.
        log("Ubuntu Pro: `pro` not found in PATH", "debug")
    else:
        log(
            "Ubuntu Pro: `pro` is installed but neither `pro api` nor "
            f"{_STATUS_CACHE_FILE} yielded a reading; reporting null",
            "error",
        )
    return None


@debug("ubuntu_pro")
def ubuntu_pro_status():
    """Collect Ubuntu Pro attachment and the services that are actually enabled.

    Returns one of:

    - ``None`` -- COULD NOT DETERMINE (`pro` absent, timed out, errored, or the
      host is not Ubuntu at all). The server preserves whatever it has stored
      and never writes ``false`` from this.
    - ``{"attached": False, "services": []}`` -- `pro` answered and the machine
      is not attached.
    - ``{"attached": True, "services": [...]}`` -- attached, with the services
      whose archive pockets are actually open. The list is empty when every
      service is disabled, which unlocks nothing.

    Cached for _CACHE_TTL, so the cost above is paid at most once per window
    however short the collection interval is.
    """
    return _cache.get_or_compute(_CACHE_KEY, _CACHE_TTL, _read)
