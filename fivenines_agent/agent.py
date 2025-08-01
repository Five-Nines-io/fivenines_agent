#!/usr/bin/python

import os
import sys
import platform
import time
import socket
import signal
from threading import Event

import psutil
import systemd_watchdog
from dotenv import load_dotenv

from fivenines_agent.env import debug_mode, dry_run
from fivenines_agent.load_average import load_average
from fivenines_agent.cpu import cpu_usage, cpu_data, cpu_model, cpu_count
from fivenines_agent.memory import memory, swap
from fivenines_agent.ip import get_ip
from fivenines_agent.network import network
from fivenines_agent.partitions import partitions_metadata, partitions_usage
from fivenines_agent.processes import processes
from fivenines_agent.io import io
from fivenines_agent.smart_storage import (
    smart_storage_identification,
    smart_storage_health,
)
from fivenines_agent.raid_storage import raid_storage_health
from fivenines_agent.files import file_handles_used, file_handles_limit
from fivenines_agent.redis import redis_metrics
from fivenines_agent.nginx import nginx_metrics
from fivenines_agent.docker import docker_metrics
from fivenines_agent.synchronizer import Synchronizer
from fivenines_agent.synchronization_queue import SynchronizationQueue
from fivenines_agent.ports import listening_ports
from fivenines_agent.debug import debug

CONFIG_DIR = "/etc/fivenines_agent"
load_dotenv(dotenv_path=os.path.join(CONFIG_DIR, '.env'))

# Exit event for safe shutdown
exit_event = Event()

class Agent:
    def __init__(self):
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT,  self._on_signal)
        signal.signal(signal.SIGHUP,  self._on_signal)

        self.version = '1.1.3'
        print(f'fivenines agent v{self.version}')

        # Load token
        self._load_file('TOKEN')

        self.queue = SynchronizationQueue(maxsize=100)
        self.synchronizer = Synchronizer(self.token, self.queue)
        self.synchronizer.start()

    def _on_signal(self, signum, frame):
        # Only set the exit flag; defer cleanup to main loop
        exit_event.set()

    def _load_file(self, filename):
        try:
            path = os.path.join(CONFIG_DIR, filename)
            with open(path, 'r') as f:
                setattr(self, filename.lower(), f.read().strip())
        except FileNotFoundError:
            print(f'{filename} file is missing', file=sys.stderr)
            sys.exit(2)

    def run(self):
        # Notify systemd watchdog
        wd = systemd_watchdog.watchdog()
        wd.ready()

        # Static info
        static_data = {
            'version': self.version,
            'uname': platform.uname()._asdict(),
            'boot_time': psutil.boot_time(),
        }

        try:
            while not exit_event.is_set():
                wd.notify()

                # Refresh config if disabled
                self.config = self.synchronizer.get_config()
                if not self.config.get('enabled', False):
                    self.queue.put({'get_config': True})
                    exit_event.wait(25)
                    continue

                data = static_data.copy()
                data['ts'] = time.time()
                start = time.monotonic()

                # Core metrics
                data['load_average'] = load_average()
                data['file_handles_used'] = file_handles_used()
                data['file_handles_limit'] = file_handles_limit()

                # Conditional metrics
                if self.config.get('ping'):
                    for region, host in self.config['ping'].items():
                        data[f'ping_{region}'] = self.tcp_ping(host)
                if self.config.get('cpu'):
                    data['cpu'] = cpu_data()
                    data['cpu_usage'] = cpu_usage()
                    data['cpu_model'] = cpu_model()
                    data['cpu_count'] = cpu_count()
                if self.config.get('memory'):
                    data['memory'] = memory()
                    data['swap'] = swap()
                if self.config.get('ipv4'):
                    data['ipv4'] = get_ip(ipv6=False)
                if self.config.get('ipv6'):
                    data['ipv6'] = get_ip(ipv6=True)
                if self.config.get('network'):
                    data['network'] = network()
                if self.config.get('partitions'):
                    data['partitions_metadata'] = partitions_metadata()
                    data['partitions_usage'] = partitions_usage()
                if self.config.get('io'):
                    data['io'] = io()
                if self.config.get('smart_storage_health'):
                    data['smart_storage_identification'] = smart_storage_identification()
                    data['smart_storage_health'] = smart_storage_health()
                if self.config.get('raid_storage_health'):
                    data['raid_storage_health'] = raid_storage_health()
                if self.config.get('processes'):
                    data['processes'] = processes()
                if self.config.get('ports'):
                    data['ports'] = listening_ports(**self.config['ports'])
                if self.config.get('redis'):
                    data['redis'] = redis_metrics(**self.config['redis'])
                if self.config.get('nginx'):
                    data['nginx'] = nginx_metrics(**self.config['nginx'])
                if self.config.get('docker'):
                    data['docker'] = docker_metrics(**self.config['docker'])

                # Running time and enqueue
                running_time = time.monotonic() - start
                data['running_time'] = running_time
                self.queue.put(data)

                # Exit immediately in dry-run
                if dry_run():
                    exit_event.set()

                # Sleep respecting interval
                self._wait_interval(running_time)

        except Exception as e:
            # Log unexpected errors before exiting
            print(f'Error: {e}', file=sys.stderr)
        finally:
            self._cleanup()

    def _wait_interval(self, running_time):
        if debug_mode():
            print(f'Running time: {running_time:.3f}s')
        interval = self.config.get('interval', 60)
        sleep_time = max(interval - running_time, 0.1)
        if debug_mode():
            print(f'Sleeping time: {sleep_time * 1000:.0f} ms')
        exit_event.wait(sleep_time)

    @debug('tcp_ping')
    def tcp_ping(self, host, port=80, timeout=5):
        try:
            start = time.time()
            with socket.create_connection((host, port), timeout):
                return (time.time() - start) * 1000
        except Exception:
            return None

    def _cleanup(self):
        print('fivenines agent shutting down. Please wait...')
        self.queue.clear()
        self.synchronizer.stop()
        self.queue.put(None)
        self.synchronizer.join()
        sys.exit(0)