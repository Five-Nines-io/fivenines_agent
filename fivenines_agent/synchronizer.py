import time
import http.client
import ssl
import certifi
import json
import gzip
from threading import Thread
from threading import Lock
from threading import Event

from fivenines_agent.env import debug_mode, api_url
from fivenines_agent.dns_resolver import DNSResolver

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
                headers['Host'] = api_url()
                conn.request('POST', '/collect', compressed_data, headers)
                res = conn.getresponse()
                body = res.read().decode("utf-8")

                if res.status == 200:
                    if debug_mode():
                        print(f'Sync time: {time.monotonic() - start_time}')
                    config = json.loads(body)['config']
                    with self.config_lock:
                        self.config = config
                    break
                else:
                    raise Exception(f'HTTP {res.status}: {body}')
            except Exception as e:
                try_count += 1
                print(f'Synchronizer Error: {e}')
                sleep_time = self.config["request_options"]["retry_interval"] * try_count
                print(f'Retrying in {sleep_time} seconds')
                # Wait for either the stop event or the timeout
                if self._stop_event.wait(timeout=sleep_time):
                    break

    def get_conn(self):
        url = api_url()
        # Use DNSResolver to resolve the API host only if it's not localhost
        if not url.startswith('localhost'):
            resolver = DNSResolver(url.split(':')[0])
            answers = resolver.resolve("A")
            if not answers:
                print(f"Could not resolve API host: {url}")
                return

            api_ip = answers[0].address
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            conn = http.client.HTTPSConnection(
                api_ip,
                timeout=self.config['request_options']['timeout'],
                context=ssl_context
            )
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
