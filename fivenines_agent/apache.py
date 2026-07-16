from urllib.parse import parse_qs, urlsplit

import requests

from fivenines_agent.debug import debug, log


# Apache HTTP Server metrics via mod_status' machine-readable endpoint
# (server-status?auto). See:
# https://httpd.apache.org/docs/2.4/mod/mod_status.html
#
# The ?auto body is a flat list of "Key: Value" lines plus a Scoreboard string.
# Which lines appear depends on the MPM and version (mpm_event adds ConnsTotal,
# Processes, Stopping, Total Duration...; mpm_prefork omits them), so this
# collector parses by key name -- never by positional index like nginx.py -- and
# tolerates any field being absent. The seven fields we read are present on both
# prefork and event, so a healthy scrape yields no None values.
#
# Example ?auto body (mpm_event, trimmed):
#   Total Accesses: 1250
#   Total kBytes: 8945
#   ReqPerSec: .345304
#   BytesPerSec: 2529.71
#   BusyWorkers: 1
#   IdleWorkers: 49
#   Scoreboard: __W_K.............

# Scoreboard character -> worker state. All eleven states are zero-filled in the
# payload so the server always receives the full distribution (waiting/reading/
# sending/keepalive/...), not just the states currently occupied.
SCOREBOARD_STATES = {
    "_": "waiting",       # Waiting for connection
    "S": "starting",      # Starting up
    "R": "reading",       # Reading request
    "W": "sending",       # Sending reply
    "K": "keepalive",     # Keepalive (read)
    "D": "dns_lookup",    # DNS lookup
    "C": "closing",       # Closing connection
    "L": "logging",       # Logging
    "G": "graceful",      # Gracefully finishing
    "I": "idle_cleanup",  # Idle cleanup of worker
    ".": "open",          # Open slot with no current process
}


@debug("apache_metrics")
def apache_metrics(status_page_url="http://127.0.0.1/server-status?auto"):
    try:
        # server-status only emits the machine-readable body with ?auto; append
        # it defensively so a URL configured without it still parses (Apache
        # would otherwise return the HTML status page, which we cannot read).
        # Scope the check to the query string: a host or path that merely
        # contains the substring "auto" (autoconfig.internal, /auto-status)
        # must not fool us into thinking the flag is already set.
        query = urlsplit(status_page_url).query
        if "auto" not in parse_qs(query, keep_blank_values=True):
            sep = "&" if query else "?"
            status_page_url = f"{status_page_url}{sep}auto"

        response = requests.get(status_page_url, timeout=5)
        if response.status_code != 200:
            return None

        # Parse into a flat key/value map on the first ":" so a value that
        # itself contains a colon stays intact, and unknown MPM/version lines
        # are simply carried along unused.
        fields = {}
        for line in response.text.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()

        def as_int(key):
            try:
                return int(fields[key])
            except (KeyError, ValueError):
                return None

        def as_float(key):
            try:
                return float(fields[key])
            except (KeyError, ValueError):
                return None

        metrics = {
            "apache_version": response.headers.get("Server"),
            "requests_per_second": as_float("ReqPerSec"),
            "bytes_per_second": as_float("BytesPerSec"),
            "busy_workers": as_int("BusyWorkers"),
            "idle_workers": as_int("IdleWorkers"),
            "total_accesses": as_int("Total Accesses"),
            "total_kbytes": as_int("Total kBytes"),
        }

        # Count scoreboard characters into every state (zero-filled). Unknown
        # characters (future Apache states) are ignored rather than dropped into
        # a bogus bucket. workers_utilization_pct is derived server-side from
        # busy/idle, so it is deliberately not computed here.
        scoreboard = {state: 0 for state in SCOREBOARD_STATES.values()}
        for char in fields.get("Scoreboard", ""):
            state = SCOREBOARD_STATES.get(char)
            if state:
                scoreboard[state] += 1
        metrics["scoreboard"] = scoreboard

        return metrics

    except Exception as e:
        log(f"Error collecting Apache metrics: {e}", "error")
        return None
