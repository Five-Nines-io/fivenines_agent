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

from dotenv import load_dotenv

load_dotenv()

def get_env(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    return value

API_URL = get_env('API_URL', 'api.five-nines.io')
API_TIMEOUT = int(get_env('API_TIMEOUT', 5)) # seconds
ROOT_PATH = get_env('ROOT_PATH', '/opt/five_nines_client')
CHECK_INTERVAL = int(get_env('CHECK_INTERVAL', 5)) # seconds

PING_REGIONS = {
    'asia': 'google.com',
    'usa': 'google.com',
    'europe': 'google.com'
}

def get_token():
    try:
        f = open(f'{ROOT_PATH}/TOKEN')
        return f.read().strip('\n')
    except FileNotFoundError:
        wd.notify_error('TOKEN file is missing')
        sys.exit(2)

def get_version():
    try:
        f = open(f'{ROOT_PATH}/VERSION')
        return f.read().rstrip('\n')
    except FileNotFoundError:
        wd.notify_error('VERSION file is missing')
        sys.exit(2)


def get_ip():
    try:
        conn = http.client.HTTPSConnection('ifconfig.io', timeout=2)
        conn.request("GET", "/ip")
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
        conn.request("POST", "/api/collect", json.dumps(data), { 'Authorization': f'Bearer {token}', 'Content-Type': 'application/json' })
    except Exception as e:
        print(e, file=sys.stderr)
        print(traceback.print_exc(), file=sys.stderr)

token = get_token()
version = get_version()
hostname = socket.gethostname()
ip = get_ip()
operating_system = platform.system()
kernel_version = platform.release()
cpu_architecture = platform.machine()
cpu_model = get_cpu_model(operating_system)

print(f'Five nines client v{version} started')

wd = systemd_watchdog.watchdog()
wd.ready()

sleep_time = CHECK_INTERVAL

while(True):
    time.sleep(sleep_time)
    start_time = time.monotonic()

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
    for k, v in psutil.net_io_counters(pernic=True).items():
        network.append({ k: v._asdict() })

    file_handles_usage, _, file_handles_limit = get_file_handles(operating_system)

    data = {
        'version': version,
        'hostname': hostname,
        'operating_system': operating_system,
        'kernel_version': kernel_version,
        'cpu_architecture': cpu_architecture,
        'cpu_model': cpu_model,
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
        'file_handles_limit': file_handles_limit
    }

    for region, ping_ip in PING_REGIONS.items():
        result = os.popen(f'ping -c 1 {ping_ip} | grep "time=" | cut -d " " -f7 | cut -d "=" -f2').read()
        data[f'ping_{region}'] = float(result.rstrip('\n'))

    send_request(data)
    wd.ping()

    sleep_time = CHECK_INTERVAL - (time.monotonic() - start_time)
    if sleep_time < 0:
        sleep_time = 0
