import time
import http.client
import ssl
import certifi
import json
import gzip
from threading import Thread
from threading import Lock
from threading import Event
import socket

from fivenines_agent.env import api_url
from fivenines_agent.dns_resolver import DNSResolver
from fivenines_agent.env import dry_run
from fivenines_agent.debug import log

class Synchronizer(Thread):
    def __init__(self, token, queue):
        Thread.__init__(self)
        self._stop_event = Event()
        self.config_lock = Lock()
        self.token = token
        self.config = { 'enabled': None, 'request_options': { 'timeout': 5, 'retry': 3, 'retry_interval': 5 } }
        self.queue = queue


    def run(self):
        # We fetch the config from the server before starting to collect metrics
        self.send_request({'get_config': True})

        while not self._stop_event.is_set():
            data = self.queue.get()
            if data is not None:
                self.send_request(data)
                self.queue.task_done()

    def stop(self):
        self._stop_event.set()

    def send_request(self, data):
        log(f'Sending request: {data}', 'debug')
        try_count = 0
        compressed_data = gzip.compress(json.dumps(data).encode('utf-8'))
        headers = {
            'Content-Type': 'application/json',
            'Content-Encoding': 'gzip',
            'Content-Length': str(len(compressed_data)),
            'Authorization': f'Bearer {self.token}'
        }

        while try_count < self.config['request_options']['retry']:
            try:
                start_time = time.monotonic()
                conn = self.get_conn()
                if conn is None:
                    raise Exception("Failed to establish connection (DNS resolution or connection setup failed)")

                conn.request('POST', '/collect', compressed_data, headers)
                res = conn.getresponse()
                body = res.read().decode("utf-8")

                if res.status == 200:
                    log(f'Sync time: {(time.monotonic() - start_time) * 1000} ms', 'debug')
                    config = json.loads(body)['config']
                    with self.config_lock:
                        self.config = config
                    break
                else:
                    raise Exception(f'HTTP {res.status}: {body}')
            except Exception as e:
                try_count += 1
                log(f'Synchronizer Error: {e}', 'error')
                sleep_time = self.config["request_options"]["retry_interval"] * try_count
                log(f'Retrying in {sleep_time} seconds', 'error')
                # Wait for either the stop event or the timeout
                if self._stop_event.wait(timeout=sleep_time):
                    break

    def get_conn(self):
        url = api_url()
        if not url.startswith('localhost'):
            try:
                resolver = DNSResolver(url.split(':')[0])
                answers = resolver.resolve("A")
                if not answers:
                    log(f"Could not resolve API host: {url}", 'error')
                    return None

                api_ip = answers[0].address
                hostname = url.split(':')[0]

                ssl_context = ssl.create_default_context(cafile=certifi.where())
                port = 443
                if ':' in url:
                    port = int(url.split(':')[1])

                sock = socket.create_connection((api_ip, port), timeout=self.config['request_options']['timeout'])
                sock = ssl_context.wrap_socket(sock, server_hostname=hostname)

                conn = http.client.HTTPSConnection(
                    hostname,
                    timeout=self.config['request_options']['timeout']
                )
                conn.sock = sock
                return conn
            except Exception as e:
                log(f"Error during DNS resolution or connection setup: {e}", 'error')
                return None
        else:
            conn = http.client.HTTPConnection(
                url,
                timeout=self.config['request_options']['timeout'],
            )
            return conn

    def get_config(self):
        if self.config['enabled'] == None:
            self.send_request({'get_config': True})
            return self.config
        else:
            with self.config_lock:
                return self.config
