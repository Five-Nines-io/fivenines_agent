#!/usr/bin/python

import os
import sys
import systemd_watchdog
import time
import platform
import psutil
import signal

from fivenines_agent.env import debug_mode
from fivenines_agent.cpu import cpu_data, cpu_model
from fivenines_agent.ip import get_ip
from fivenines_agent.network import network
from fivenines_agent.partitions import partitions_metadata, partitions_usage
from fivenines_agent.processes import processes
from fivenines_agent.disks import io
from fivenines_agent.files import file_handles_used, file_handles_limit
from fivenines_agent.redis import redis_metrics
from fivenines_agent.nginx import nginx_metrics
from fivenines_agent.synchronizer import Synchronizer
from fivenines_agent.synchronization_queue import SynchronizationQueue

CONFIG_DIR = "/etc/fivenines_agent"
from dotenv import load_dotenv
load_dotenv(dotenv_path=f'{CONFIG_DIR}/.env')

class Agent:
    def __init__(self):
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)

        self.version = '0.0.3'

        for file in ["TOKEN"]:
            self.load_file(file)

        self.queue = SynchronizationQueue(maxsize=100)
        self.synchronizer = Synchronizer(self.token, self.queue)
        self.synchronizer.start()

    def shutdown(self, _signum, _frame):
        self.queue.clear()
        self.queue.put(None)
        self.synchronizer.join()
        sys.exit(0)

    def load_file(self, file):
        try:
            with open(f'{CONFIG_DIR}/{file}', 'r') as f:
                setattr(self, file.lower(), f.read().rstrip('\n'))
        except FileNotFoundError:
            print(f'{file} file is missing')
            sys.exit(2)

    def run(self):
        wd = systemd_watchdog.watchdog()
        wd.ready()

        static_data = {
            'version': self.version,
            'uname': platform.uname()._asdict(),
            'boot_time': psutil.boot_time(),
        }

        while True:
            try:
                wd.ping()
                self.config = self.synchronizer.get_config()

                if self.config['enabled'] == False:
                    self.wait(25)
                    continue

                data = static_data.copy()
                start_time = time.monotonic()
                ts = time.time()
                data['ts'] = ts
                data['load_average'] = psutil.getloadavg()
                data['file_handles_used'] = file_handles_used()
                data['file_handles_limit'] = file_handles_limit()

                if self.config['ping']:
                    for region, host in self.config['ping'].items():
                        data[f'ping_{region}'] = self.ping(host)

                if self.config['cpu']:
                    data['cpu'] = cpu_data()
                    data['cpu_model'] = cpu_model()
                    data['cpu_count'] = os.cpu_count()

                if self.config['memory']:
                    data['memory'] = psutil.virtual_memory()._asdict()
                    data['swap'] = psutil.swap_memory()._asdict()

                if self.config['ipv4']:
                    data['ipv4'] = get_ip(4)

                if self.config['ipv6']:
                    data['ipv6'] = get_ip(6)

                if self.config['network']:
                    data['network'] = network()

                if self.config['partitions']:
                    data['partitions_metadata'] = partitions_metadata()
                    data['partitions_usage'] = partitions_usage()

                if self.config['io']:
                    data['io'] = io()

                if self.config['processes']:
                    data['processes'] = processes()

                if self.config['redis']:
                    data['redis'] = redis_metrics(**self.config['redis'])

                if self.config['nginx']:
                    data['nginx'] = nginx_metrics()

                self.queue.put(data)
                self.wait(start_time)

            except KeyboardInterrupt:
                self.shutdown()

    def wait(self, start_time):
        running_time = time.monotonic() - start_time

        if debug_mode():
            print(f'Running time: {running_time}')

        if running_time < self.config['interval']:
            sleep_time = self.config['interval'] - running_time
        else:
            sleep_time = 0.1

        if debug_mode():
            print(f'Sleeping for {sleep_time} seconds')
        time.sleep(sleep_time)

    def ping(self, host):
        f = os.popen(f'ping -c 1 {host} -t 5 | grep "time=" | cut -d " " -f7 | cut -d "=" -f2', 'r')
        result = f.read().rstrip('\n')
        status = f.close()

        if debug_mode():
            print(f'ping_{host}: {repr(result)}')

        if status != 0:
            return None
        return float(result)
