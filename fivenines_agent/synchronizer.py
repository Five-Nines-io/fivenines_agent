import gzip
import http.client
import json
import os
import socket
import ssl
import threading
import time
from threading import Event, Lock, Thread

import certifi

from fivenines_agent.debug import debug, debug_enabled, log
from fivenines_agent.dns_resolver import DNSResolver
from fivenines_agent.env import api_url, config_dir

# gzip level for every POST body. The library default (9) is the slowest
# setting for a ~2-5% size win on JSON; level 6 is the standard speed/ratio
# trade and this code runs on every payload of every tick.
GZIP_LEVEL = 6

# Process-wide TLS context. Building one re-parses the whole CA bundle
# (~200KB of PEM), which is pure per-request waste before this was cached. The
# context is only ever used to wrap_socket, which is thread-safe.
_ssl_context = None
_ssl_context_lock = Lock()


def _get_ssl_context():
    global _ssl_context
    with _ssl_context_lock:
        if _ssl_context is None:
            # Use certifi if bundled, otherwise fallback to system CA certificates
            cert_path = certifi.where()
            if os.path.exists(cert_path):
                _ssl_context = ssl.create_default_context(cafile=cert_path)
            else:
                _ssl_context = ssl.create_default_context()
        return _ssl_context


def serialize_payload(data):
    """json+gzip a payload for enqueueing.

    The agent compresses metric payloads BEFORE they enter the buffering
    queue: a 100-deep queue of raw payload dicts is hundreds of MB of Python
    object graphs during an API outage (dict overhead is ~5-10x the JSON
    size), while the same backlog compressed is a few MB. _post sends bytes
    input as-is instead of re-serializing.
    """
    return gzip.compress(json.dumps(data).encode("utf-8"), compresslevel=GZIP_LEVEL)


class _HTTPStatusError(Exception):
    """Non-200 HTTP response. Distinct from transport errors so a reused
    connection's stale-socket rebuild (free, no retry consumed) never applies
    to a real server-side error -- that would double every request against an
    erroring API."""


class Synchronizer(Thread):
    def __init__(self, token, queue, static_data=None):
        Thread.__init__(self)
        self._stop_event = Event()
        self.config_lock = Lock()
        # Single-flight guard: at most one get_config fetch in flight at a
        # time, across the startup fetch (run) and the main loop (get_config).
        self._config_fetch_lock = Lock()
        self.token = token
        self.config = {
            "enabled": None,
            "request_options": {"timeout": 5, "retry": 3, "retry_interval": 5},
        }
        self.queue = queue
        self.static_data = static_data or {}
        # Per-thread persistent connection. _post runs on the synchronizer
        # thread AND the uploader threads (send_logs / send_image_packages),
        # and http.client connections are not thread-safe, so each thread
        # keeps its own -- reused across requests to skip the per-POST DNS
        # query + TCP connect + TLS handshake this code used to pay.
        self._conn_local = threading.local()

    def run(self):
        # We fetch the config from the server before starting to collect metrics
        self._fetch_config_once()

        while not self._stop_event.is_set():
            data = self.queue.get()
            if data is not None:
                self.send_metrics(data)
                self.queue.task_done()

    def stop(self):
        self._stop_event.set()

    def _acquire_conn(self):
        """Cached connection for this thread, creating one when absent."""
        conn = getattr(self._conn_local, "conn", None)
        if conn is None:
            conn = self.get_conn()
            self._conn_local.conn = conn
        return conn

    def _has_cached_conn(self):
        return getattr(self._conn_local, "conn", None) is not None

    def _discard_conn(self):
        """Close and forget this thread's cached connection (if any)."""
        conn = getattr(self._conn_local, "conn", None)
        self._conn_local.conn = None
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    def _post(self, endpoint, data):
        """Generic POST with gzip, auth, and retries. Returns parsed JSON or None.

        *data* is either a dict (serialized + compressed here) or bytes already
        produced by serialize_payload (metric payloads are compressed at
        enqueue time so the buffering queue stays small).
        """
        if isinstance(data, (bytes, bytearray)):
            compressed_data = bytes(data)
            # Keep the in-flight request visible to a debugging operator even
            # on the pre-compressed path (the /collect common case).
            if debug_enabled():
                log(
                    f"Sending request to {endpoint}: "
                    f"<precompressed {len(compressed_data)} bytes>",
                    "debug",
                )
        else:
            # Gate on debug_enabled: log() checks the level only after the
            # argument is built, and str() of a full payload dict is real
            # per-request CPU at any log level without this guard.
            if debug_enabled():
                log(f"Sending request to {endpoint}: {data}", "debug")

            with debug("json_serialize") as d:
                json_data = json.dumps(data).encode("utf-8")
                d.result = f"{len(json_data)} bytes"

            with debug("gzip_compress") as d:
                compressed_data = gzip.compress(json_data, compresslevel=GZIP_LEVEL)
                d.result = f"{len(json_data)} -> {len(compressed_data)} bytes ({100 - len(compressed_data) * 100 // len(json_data)}% reduction)"
        headers = {
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "Content-Length": str(len(compressed_data)),
            "Authorization": f"Bearer {self.token}",
        }

        try_count = 0
        while try_count < self.config["request_options"]["retry"]:
            reused = self._has_cached_conn()
            try:
                start_time = time.monotonic()
                conn = self._acquire_conn()
                if conn is None:
                    raise Exception(
                        "Failed to establish connection (DNS resolution or connection setup failed)"
                    )

                conn.request("POST", endpoint, compressed_data, headers)
                res = conn.getresponse()
                body = res.read().decode("utf-8")

                if res.status == 200:
                    log(
                        f"Sync time: {(time.monotonic() - start_time) * 1000} ms",
                        "debug",
                    )
                    return json.loads(body)
                else:
                    raise _HTTPStatusError(f"HTTP {res.status}: {body}")
            except Exception as e:
                if isinstance(e, _HTTPStatusError):
                    # The error body was fully drained (res.read() above), so
                    # the connection itself is healthy and reusable. Closing
                    # it here would make every retry against an ERRORING API
                    # (a 429/500 burst) pay a fresh DNS + TCP + TLS handshake
                    # -- a fleet-wide reconnect storm against a server that is
                    # already struggling. If the server also sent
                    # "Connection: close", auto_open=0 surfaces that as a
                    # transport error on the next attempt, which rebuilds.
                    pass
                else:
                    self._discard_conn()
                if reused and not isinstance(e, _HTTPStatusError):
                    # A kept-alive socket the server closed between requests
                    # fails on first reuse. Rebuild once without consuming a
                    # retry or logging an error -- this is the expected cost
                    # of connection reuse, not a real failure. The rebuilt
                    # attempt starts with no cached conn, so a second failure
                    # in a row is counted normally.
                    log(f"Reconnecting after stale connection: {e}", "debug")
                    continue
                try_count += 1
                log(f"Synchronizer Error: {e}", "error")
                sleep_time = (
                    self.config["request_options"]["retry_interval"] * try_count
                )
                log(f"Retrying in {sleep_time} seconds", "error")
                # Wait for either the stop event or the timeout
                if self._stop_event.wait(timeout=sleep_time):
                    break

        return None

    def send_metrics(self, data):
        """Send metrics to /collect and update config from response."""
        response = self._post("/collect", data)
        if response is not None:
            if "token" in response:
                self._swap_token(response["token"])
            config = response["config"]
            with self.config_lock:
                self.config = config

    def _swap_token(self, new_token):
        """Persist the per-host token received after enrollment."""
        log("Received per-host token, saving...", "info")
        self.token = new_token
        token_path = os.path.join(config_dir(), "TOKEN")
        try:
            with open(token_path, "w") as f:
                f.write(new_token)
            log("Token swapped successfully", "info")
        except PermissionError:
            log(f"Permission denied writing to {token_path}. Proceeding with in-memory token.", "warn")
        except Exception as e:
            log(f"Error saving token: {e}", "error")

    def send_packages(self, packages_data):
        """Send packages data to /packages. Returns response or None."""
        return self._post("/packages", packages_data)

    def send_logs(self, bundle):
        """Send a log-capture bundle to /logs. Returns response or None.

        Mirrors send_packages: gzip + auth + bounded retries via _post. Called
        from the dedicated LogUploader thread (not the collection loop or the
        /collect synchronizer drain), so a slow/large upload never blocks metric
        collection or config sync.
        """
        return self._post("/logs", bundle)

    def send_systemd_inventory(self, inventory_data):
        """Send systemd inventory snapshot to /systemd_inventory. Returns response or None."""
        return self._post("/systemd_inventory", inventory_data)

    def send_image_packages(self, image_packages_data):
        """Send one Docker image's OS package inventory to /image_packages.
        Returns the parsed response (truthy) on a 200, None otherwise.

        Mirrors send_packages / send_logs: gzip + auth + bounded retries via
        _post. Called from the dedicated ImageInventoryUploader thread (never the
        collection loop or the /collect drain), so a slow upload cannot block
        metric collection or config sync. The server answers 200 for every
        definitive outcome including refusals (so the digest is marked done and
        not retried); non-200 is transient only."""
        return self._post("/image_packages", image_packages_data)

    def get_conn(self):
        url = api_url()
        if not url.startswith("localhost"):
            hostname = url.split(":")[0]
            port = 443
            if ":" in url:
                port = int(url.split(":")[1])

            resolver = DNSResolver(hostname)
            ssl_context = _get_ssl_context()

            # Try IPv4 first, then fallback to IPv6
            for record_type, af in [("A", socket.AF_INET), ("AAAA", socket.AF_INET6)]:
                sock = None
                try:
                    answers = resolver.resolve(record_type)
                    if not answers:
                        continue

                    api_ip = answers[0].address
                    log(f"Trying {record_type} ({api_ip}) for {hostname}", "debug")

                    sock = socket.socket(af, socket.SOCK_STREAM)
                    sock.settimeout(self.config["request_options"]["timeout"])
                    sock.connect((api_ip, port))
                    sock = ssl_context.wrap_socket(sock, server_hostname=hostname)

                    conn = http.client.HTTPSConnection(
                        hostname, timeout=self.config["request_options"]["timeout"]
                    )
                    conn.sock = sock
                    # The connection is cached and reused across requests now.
                    # Without this, a server-side "Connection: close" leaves
                    # sock=None on the cached conn and http.client's auto_open
                    # silently RECONNECTS through its own connect(): system
                    # getaddrinfo (bypassing our resolver + IPv4/IPv6
                    # fallback), a default system-CA context (bypassing the
                    # bundled certifi trust root the PyInstaller build relies
                    # on) and default port 443 (ignoring a custom api_url
                    # port). auto_open=0 makes that state raise NotConnected
                    # instead, which flows into _post's free stale-connection
                    # rebuild through this function's intended path.
                    conn.auto_open = 0
                    log(f"Connected via {record_type} ({api_ip})", "debug")
                    return conn
                except Exception as e:
                    # Close the half-open socket rather than leaving the fd to
                    # the GC: a failed connect/wrap per attempt per retry adds
                    # up during a long API outage.
                    if sock is not None:
                        try:
                            sock.close()
                        except Exception:
                            pass
                    log(f"Failed to connect via {record_type}: {e}", "debug")
                    continue

            log(
                f"Could not connect to API host: {hostname} (tried IPv4 and IPv6)",
                "error",
            )
            return None
        else:
            conn = http.client.HTTPConnection(
                url,
                timeout=self.config["request_options"]["timeout"],
            )
            return conn

    def _fetch_config_once(self, wait_timeout=0):
        """Fire one get_config fetch unless another is already in flight.

        Both the startup fetch (run) and the main loop (get_config) land here
        while self.token can still be an ENROLLMENT token; two concurrent
        fetches enroll the same machine twice and mint a duplicate host (the
        server dedup key is machine_id, which not every install can persist).
        A failed fetch releases the guard so a later call retries: one in
        flight, not one ever. The recheck under config_lock closes the window
        where the winning fetch already populated the config before we got
        the guard.

        On contention the loser never fetches. With wait_timeout it may wait
        (bounded) for the in-flight fetch to finish -- so a healthy startup
        ticks as soon as the config lands instead of a poll interval later --
        but it returns without fetching even if that fetch failed: stacking a
        wait plus a fresh retry ladder (~45s each) in one loop iteration
        could outlast the systemd watchdog (90s). The next loop pass finds
        the guard free and retries as the fetcher.
        """
        if not self._config_fetch_lock.acquire(blocking=False):
            if wait_timeout and self._config_fetch_lock.acquire(
                timeout=wait_timeout
            ):
                self._config_fetch_lock.release()
            return
        try:
            with self.config_lock:
                if self.config["enabled"] is not None:
                    return
            self.send_metrics({"get_config": True, **self.static_data})
        finally:
            self._config_fetch_lock.release()

    def get_config(self):
        with self.config_lock:
            config = self.config
        if config["enabled"] is None:
            # 45s: enough to sit out the startup fetch's full retry ladder in
            # the common case, while keeping this call (plus the caller's 25s
            # disabled-branch wait) under the 90s systemd watchdog.
            self._fetch_config_once(wait_timeout=45)
            with self.config_lock:
                return self.config
        return config
