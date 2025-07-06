#!/usr/bin/python

import os
import sys
import systemd_watchdog
import time
import platform
import psutil
import signal
import socket
from threading import Event

from fivenines_agent.env import debug_mode
from fivenines_agent.load_average import load_average
from fivenines_agent.cpu import cpu_data, cpu_model, cpu_count
from fivenines_agent.memory import memory, swap
from fivenines_agent.ip import get_ip
from fivenines_agent.network import network
from fivenines_agent.partitions import partitions_metadata, partitions_usage
from fivenines_agent.processes import processes
from fivenines_agent.io import io
from fivenines_agent.smart_storage import smart_storage_identification, smart_storage_health
from fivenines_agent.raid_storage import raid_storage_health
from fivenines_agent.files import file_handles_used, file_handles_limit
from fivenines_agent.redis import redis_metrics
from fivenines_agent.nginx import nginx_metrics
from fivenines_agent.docker import docker_metrics
from fivenines_agent.synchronizer import Synchronizer
from fivenines_agent.synchronization_queue import SynchronizationQueue
from fivenines_agent.ports import listening_ports
from fivenines_agent.debug import debug
from fivenines_agent.env import dry_run

CONFIG_DIR = "/etc/fivenines_agent"
from dotenv import load_dotenv
load_dotenv(dotenv_path=f'{CONFIG_DIR}/.env')
exit = Event()

class Agent:
    def __init__(self):
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGHUP, self.shutdown)

        self.version = '1.1.3'

        print(f'fivenines agent v{self.version}')

        for file in ["TOKEN"]:
            self.load_file(file)

        self.queue = SynchronizationQueue(maxsize=100)
        self.synchronizer = Synchronizer(self.token, self.queue)
        self.synchronizer.start()

    def shutdown(self, _signum, _frame):
        print('fivenines agent shutting down. Please wait...')
        self.queue.clear()
        self.synchronizer.stop()
        self.queue.put(None)
        self.synchronizer.join()
        exit.set()
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

        while not exit.is_set():
            try:
                wd.notify()

                self.config = self.synchronizer.get_config()
                if not self.config['enabled']:
                    # If the agent is disabled, refresh the config every 25 seconds
                    self.queue.put({'get_config': True})
                    exit.wait(25)
                    continue

                data = static_data.copy()
                start_time = time.monotonic()
                data['ts'] = time.time()
                data['load_average'] = load_average()
                data['file_handles_used'] = file_handles_used()
                data['file_handles_limit'] = file_handles_limit()

                if self.config['ping']:
                    for region, host in self.config['ping'].items():
                        data[f'ping_{region}'] = self.tcp_ping(host)

                if self.config['cpu']:
                    data['cpu'] = cpu_data()
                    data['cpu_model'] = cpu_model()
                    data['cpu_count'] = cpu_count()

                if self.config['memory']:
                    data['memory'] = memory()
                    data['swap'] = swap()

                if self.config['ipv4']:
                    data['ipv4'] = get_ip(ipv6=False)

                if self.config['ipv6']:
                    data['ipv6'] = get_ip(ipv6=True)

                if self.config['network']:
                    data['network'] = network()

                if self.config['partitions']:
                    data['partitions_metadata'] = partitions_metadata()
                    data['partitions_usage'] = partitions_usage()

                if self.config['io']:
                    data['io'] = io()

                if self.config['smart_storage_health']:
                    data['smart_storage_identification'] = smart_storage_identification()
                    data['smart_storage_health'] = smart_storage_health()

                if self.config['raid_storage_health']:
                    data['raid_storage_health'] = raid_storage_health()

                if self.config['processes']:
                    data['processes'] = processes()

                if self.config['ports']:
                    data['ports'] = listening_ports()

                if self.config['redis']:
                    data['redis'] = redis_metrics(**self.config['redis'])

                if self.config['nginx']:
                    data['nginx'] = nginx_metrics(**self.config['nginx'])

                if self.config['docker']:
                    data['docker'] = docker_metrics(**self.config['docker'])

                running_time = time.monotonic() - start_time
                data['running_time'] = running_time
                self.queue.put(data)

                if dry_run():
                    self.shutdown(None, None)

                self.wait(running_time)

            except KeyboardInterrupt:
                self.shutdown(None, None)

    def wait(self, running_time):
        if debug_mode():
            print(f'Running time: {running_time}')

        if running_time < self.config['interval']:
            sleep_time = self.config['interval'] - running_time
        else:
            sleep_time = 0.1

        if debug_mode():
            print(f'Sleeping time: {sleep_time * 1000} ms')
        exit.wait(sleep_time)

    @debug('tcp_ping')
    def tcp_ping(self, host, port=80, timeout=5):
        try:
            start_time = time.time()
            with socket.create_connection((host, port), timeout):
                end_time = time.time()
                ms = (end_time - start_time) * 1000
                return ms
        except (socket.timeout, socket.error):
            return None
