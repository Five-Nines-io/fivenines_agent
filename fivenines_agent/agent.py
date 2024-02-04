#!/usr/bin/python

import os
import sys
import systemd_watchdog
import http.client
import time
import traceback
import json
import platform
import psutil

from fivenines_agent.env import api_url, debug_mode
from fivenines_agent.cpu import cpu_data, cpu_model
from fivenines_agent.ip import ipv4, ipv6
from fivenines_agent.network import network
from fivenines_agent.partitions import partitions_metadata, partitions_usage
from fivenines_agent.processes import processes
from fivenines_agent.disks import io
from fivenines_agent.files import file_handles_used, file_handles_limit

CONFIG_DIR = "/etc/fivenines_agent"
from dotenv import load_dotenv
load_dotenv(dotenv_path=f'{CONFIG_DIR}/.env')

class Agent:
    def __init__(self):
        for file in ["TOKEN"]:
            self.load_file(file)

        self.version = '0.1.2'
        self.config = {"request_options": {"timeout": 5}}
        self.config = self.sync({"get_config": True})['config']

    def load_file(self, file):
        print(f'{CONFIG_DIR}/{file}')
        try:
            with open(f'{CONFIG_DIR}/{file}', 'r') as f:
                setattr(self, file.lower(), f.read().rstrip('\n'))
        except FileNotFoundError:
            print(f'{file} file is missing')
            sys.exit(2)

    def run(self):
        wd = systemd_watchdog.watchdog()
        wd.ready()

        while True:
            wd.ping()

            if self.config['enabled'] == False:
                self.wait(25)
                continue

            start_time = time.monotonic()
            data = {}

            data['version'] = self.version
            data['uname'] = platform.uname()._asdict()
            data['boot_time'] = psutil.boot_time()
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
                data['ipv4'] = ipv4()
            if self.config['ipv6']:
                data['ipv6'] = ipv6()

            if self.config['network']:
                data['network'] = network()

            if self.config['partitions']:
                data['partitions_metadata'] = partitions_metadata()
                data['partitions_usage'] = partitions_usage()

            if self.config['io']:
                data['io'] = io()

            if self.config['processes']:
                data['processes'] = processes()

            new_config = self.sync(data)

            if new_config['config'] != None and new_config['config'] != self.config:
                self.config = new_config['config']
            self.wait(start_time)

    def wait(self, start_time):
        sleep_time = self.config['interval'] - (time.monotonic() - start_time)
        if sleep_time < 0:
            sleep_time = 0

        if debug_mode():
            print(f'Sleeping for {sleep_time} seconds')
        time.sleep(sleep_time)

    def ping(self, host):
        with os.popen(f'ping -c 1 {host} | grep "time=" | cut -d " " -f7 | cut -d "=" -f2', 'r') as f:
            result = f.read().rstrip('\n')
        if debug_mode():
            print(f'ping_{host}: {repr(result)}')

        if result != '':
            return float(result)

    def sync(self, data):
        try:
            conn = http.client.HTTPSConnection(
                api_url(), timeout=self.config['request_options']['timeout'])
            res = conn.request('POST', '/collect', json.dumps(data), {
                               'Authorization': f'Bearer {self.token}', 'Content-Type': 'application/json'})
            res = conn.getresponse()
            body = res.read().decode("utf-8")

            if debug_mode():
                print(f'Status: {res.status}')
                print(f'Response: {body}')

            return json.loads(body)
        except Exception as e:
            print(e, file=sys.stderr)
            print(traceback.print_exc(), file=sys.stderr)
