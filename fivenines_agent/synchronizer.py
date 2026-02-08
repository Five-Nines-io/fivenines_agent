import gzip
import http.client
import json
import socket
import ssl
import time
from threading import Event, Lock, Thread

import certifi

from fivenines_agent.debug import debug, log
from fivenines_agent.dns_resolver import DNSResolver
from fivenines_agent.env import api_url


class Synchronizer(Thread):
    def __init__(self, token, queue):
        Thread.__init__(self)
        self._stop_event = Event()
        self.config_lock = Lock()
        self.token = token
        self.config = {
            "enabled": None,
            "request_options": {"timeout": 5, "retry": 3, "retry_interval": 5},
        }
        self.queue = queue

    def run(self):
        # We fetch the config from the server before starting to collect metrics
        self.send_metrics({"get_config": True})

        while not self._stop_event.is_set():
            data = self.queue.get()
            if data is not None:
                self.send_metrics(data)
                self.queue.task_done()

    def stop(self):
        self._stop_event.set()

    def _post(self, endpoint, data):
        """Generic POST with gzip, auth, and retries. Returns parsed JSON or None."""
        log(f"Sending request to {endpoint}: {data}", "debug")
        try_count = 0

        with debug("json_serialize") as d:
            json_data = json.dumps(data).encode("utf-8")
            d.result = f"{len(json_data)} bytes"

        with debug("gzip_compress") as d:
            compressed_data = gzip.compress(json_data)
            d.result = f"{len(json_data)} -> {len(compressed_data)} bytes ({100 - len(compressed_data) * 100 // len(json_data)}% reduction)"
        headers = {
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "Content-Length": str(len(compressed_data)),
            "Authorization": f"Bearer {self.token}",
        }

        while try_count < self.config["request_options"]["retry"]:
            try:
                start_time = time.monotonic()
                conn = self.get_conn()
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
                    raise Exception(f"HTTP {res.status}: {body}")
            except Exception as e:
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
            config = response["config"]
            with self.config_lock:
                self.config = config

    def send_packages(self, packages_data):
        """Send packages data to /packages. Returns response or None."""
        return self._post("/packages", packages_data)

    def get_conn(self):
        url = api_url()
        if not url.startswith("localhost"):
            hostname = url.split(":")[0]
            port = 443
            if ":" in url:
                port = int(url.split(":")[1])

            resolver = DNSResolver(hostname)
            ssl_context = ssl.create_default_context(cafile=certifi.where())

            # Try IPv4 first, then fallback to IPv6
            for record_type, af in [("A", socket.AF_INET), ("AAAA", socket.AF_INET6)]:
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
                    log(f"Connected via {record_type} ({api_ip})", "debug")
                    return conn
                except Exception as e:
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

    def get_config(self):
        if self.config["enabled"] == None:
            self.send_metrics({"get_config": True})
            return self.config
        else:
            with self.config_lock:
                return self.config
