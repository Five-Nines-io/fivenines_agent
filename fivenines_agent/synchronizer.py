import time
import http.client
import ssl
import certifi
import json
import gzip
from threading import Thread
from threading import Lock

from fivenines_agent.env import debug_mode, api_url

class Synchronizer(Thread):
    def __init__(self, token, queue):
        Thread.__init__(self)
        self.config_lock = Lock()
        self.token = token
        self.config = { 'enabled': False, 'request_options': { 'timeout': 5, 'retry': 3, 'retry_interval': 5 } }
        self.queue = queue

        self.send_request({'get_config': True})

    def run(self):
        while True:
            data = self.queue.get()
            if data == None:
                break

            self.send_request(data)
            self.queue.task_done()

    def send_request(self, data):
        try_count = 0
        compressed_data = gzip.compress(json.dumps(data).encode('utf-8'))
        headers = {
            'Content-Type': 'application/json',
            'Content-Encoding': 'gzip',
            'Content-Length': str(len(compressed_data)),
            'Authorization': f'Bearer {self.token}'
        }

        ssl_context = ssl.create_default_context(cafile=certifi.where())
        while try_count < self.config['request_options']['retry']:
            try:
                start_time = time.monotonic()
                conn = http.client.HTTPSConnection(
                    api_url(), timeout=self.config['request_options']['timeout'], context=ssl_context)
                res = conn.request('POST', '/collect', compressed_data, headers)
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
                print(f'Retrying in {self.config["request_options"]["retry_interval"] * try_count} seconds')
                time.sleep(self.config['request_options']['retry_interval'] * try_count)

    def get_config(self):
        with self.config_lock:
            return self.config
