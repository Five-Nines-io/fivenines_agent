import os
import sys
import socket
import traceback
import time
import json
import http.client
import systemd_watchdog
import psutil
import platform
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()

def get_env(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    return value

API_URL = get_env('API_URL', 'api.five-nines.io')
API_TIMEOUT = int(get_env('API_TIMEOUT', 5)) # seconds
CHECK_INTERVAL = int(get_env('CHECK_INTERVAL', 5)) # seconds
DEBUG_MODE = get_env('DEBUG_MODE', 'false') == 'true'

PING_REGIONS = {
    'asia': 'asia.fivenines.io',
    'usa': 'us.fivenines.io',
    'europe': 'eu.fivenines.io'
}

def get_token():
    try:
        f = open(f'TOKEN')
        return f.read().strip('\n')
    except FileNotFoundError:
        wd.notify_error('TOKEN file is missing')
        sys.exit(2)

def get_version():
    try:
        f = open(f'VERSION')
        return f.read().rstrip('\n')
    except FileNotFoundError:
        wd.notify_error('VERSION file is missing')
        sys.exit(2)


def get_ip():
    try:
        conn = http.client.HTTPSConnection('ip.fivenines.io', timeout=2)
        conn.request("GET", "/")
        res = conn.getresponse()
        return res.read().decode("utf-8").rstrip('\n')
    except Exception as e:
        print(e, file=sys.stderr)
        print(traceback.print_exc(), file=sys.stderr)
        return '-'

def get_cpu_model(operating_system):
    if operating_system == 'Linux':
        try:
            f = open('/proc/cpuinfo')
            for line in f:
                if line.startswith('model name'):
                    return line.split(':')[1].strip()
        except FileNotFoundError:
            wd.notify_error('CPU info file is missing')
            return '-'
    elif operating_system == 'Darwin':
        try:
            return os.popen('/usr/sbin/sysctl -n machdep.cpu.brand_string').read().strip()
        except FileNotFoundError:
            wd.notify_error('CPU info file is missing')
            return '-'
    else:
        '-'

def get_network_interfaces(operating_system):
    if operating_system == 'Linux':
        return os.popen("ls -l /sys/class/net/ | grep -v virtual | grep devices | cut -d ' ' -f9").read().strip().split("\n")
    elif operating_system == 'Darwin':
        return os.popen("scutil --nwi | grep 'Network interfaces' | cut -d ' ' -f3").read().strip().split("\n")
    else:
        return []



def get_file_handles(operating_system):
    if operating_system != 'Linux':
        return [0, 0, 0]
    else:
        try:
            f = open('/proc/sys/fs/file-nr')
            return map(int, f.read().strip().split('\t'))
        except FileNotFoundError:
            wd.notify_error('File handles file is missing')
            return [0, 0, 0]


def send_request(data):
    try:
        conn = http.client.HTTPSConnection(API_URL, timeout=API_TIMEOUT)
        res = conn.request('POST', '/collect', json.dumps(data), { 'Authorization': f'Bearer {token}', 'Content-Type': 'application/json' })
        res = conn.getresponse()
        if DEBUG_MODE:
            print(f'Status: {res.status}')
            print(f'Response: {res.read().decode("utf-8")}')
    except Exception as e:
        print(e, file=sys.stderr)
        print(traceback.print_exc(), file=sys.stderr)

def get_processes(operating_system):
    processes = []
    attrs = [
        'pid',
        'ppid',
        'name',
        'username',
        'create_time',
        'memory_percent',
        'memory_full_info',
        'cpu_percent',
        'cpu_times',
        'num_fds',
        'cwd',
        'nice',
        'num_threads',
        'status',
        'connections',
        'threads'
    ]
    if operating_system == 'Linux':
        attrs.append('io_counters')

    for proc in psutil.process_iter(attrs=attrs):
        try:
            process = proc.as_dict(attrs=attrs)
            processes.append(process)
        except psutil.NoSuchProcess:
            pass
    return processes

token = get_token()
version = get_version()
ip = get_ip()
uname = platform.uname()
operating_system = uname.system
cpu_model = get_cpu_model(operating_system)

print(f'Five nines client v{version} started')

wd = systemd_watchdog.watchdog()
wd.ready()

sleep_time = CHECK_INTERVAL

while(True):
    time.sleep(sleep_time)
    start_time = time.monotonic()

    if DEBUG_MODE:
        print(f'Collecting data at {datetime.now()}')

    cpu_times_percent = psutil.cpu_times_percent(percpu=True)
    cpu_percent = psutil.cpu_percent(percpu=True)
    cpus_usage = []
    for i, v in enumerate(cpu_times_percent):
        _cpu_usage = { 'percentage': cpu_percent[i] }
        _cpu_usage.update(v._asdict())
        cpus_usage.append(_cpu_usage)

    partitions_metadata = []
    partitions_usage = {}
    for _, v in enumerate(psutil.disk_partitions(all=False)):
        partitions_metadata.append(v._asdict())
        partitions_usage[v.mountpoint] = psutil.disk_usage(v.mountpoint)._asdict()

    io = []
    for k, v in psutil.disk_io_counters(perdisk=True).items():
        io.append({ k: v._asdict()})

    network = []
    network_interfaces = get_network_interfaces(operating_system)

    for k, v in psutil.net_io_counters(pernic=True).items():
        if k not in network_interfaces:
            continue
        network.append({ k: v._asdict() })

    file_handles_usage, _, file_handles_limit = get_file_handles(operating_system)

    data = {
        'version': version,
        'uname': uname._asdict(),
        'cpu_model': cpu_model,
        'cpu_count': psutil.cpu_count(),
        'ip': ip,
        'boot_time': psutil.boot_time(),
        'load_average': psutil.getloadavg(),
        'memory': psutil.virtual_memory()._asdict(),
        'swap': psutil.swap_memory()._asdict(),
        'partitions_metadata': partitions_metadata,
        'partitions_usage': partitions_usage,
        'cpu': cpus_usage,
        'io': io,
        'network': network,
        'file_handles_usage': file_handles_usage,
        'file_handles_limit': file_handles_limit,
        'processes': get_processes(operating_system),
    }

    for region, ping_ip in PING_REGIONS.items():
        result = os.popen(f'ping -c 1 {ping_ip} | grep "time=" | cut -d " " -f7 | cut -d "=" -f2').read().rstrip('\n')
        if DEBUG_MODE:
            print(f'ping_{region}: {result}')
        data[f'ping_{region}'] = float(result)

    send_request(data)
    wd.ping()

    sleep_time = CHECK_INTERVAL - (time.monotonic() - start_time)
    if sleep_time < 0:
        sleep_time = 0
    if DEBUG_MODE:
        print(f'Sleeping for {sleep_time} seconds')
