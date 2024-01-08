import os
import sys
import traceback
import time
import json
import http.client
import systemd_watchdog
import psutil

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

def get_token():
    try:
        f = open(f'{ROOT_PATH}/TOKEN')
        return f.read().strip('\n')
    except FileNotFoundError:
        wd.notify_error('TOKEN file is missing')
        sys.exit(2)

def get_version():
    f = open(f'{ROOT_PATH}/VERSION')
    return f.read().strip('\n')

def send_request(data):
    try:
        conn.request("POST", "", json.dumps(data), { 'Authorize': f'Bearer {token}' })
    except Exception as e:
        print(e, file=sys.stderr)
        print(traceback.print_exc(), file=sys.stderr)

token = get_token()
version = get_version()
print(f'Five nines client v{version} started')

wd = systemd_watchdog.watchdog()
wd.ready()

sleep_time = CHECK_INTERVAL
conn = http.client.HTTPSConnection(API_URL, timeout=API_TIMEOUT)

while(True):
    time.sleep(sleep_time)
    start_time = time.monotonic()

    cpu_times = psutil.cpu_times(percpu=True)
    cpu_percent = psutil.cpu_percent(percpu=True)
    cpus_usage = []
    for i, v in enumerate(cpu_times):
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

    data = {
        'version': version,
        'boot_time': psutil.boot_time(),
        'load_average': psutil.getloadavg(),
        'memory': psutil.virtual_memory()._asdict(),
        'swap': psutil.swap_memory()._asdict(),
        'partitions_metadata': partitions_metadata,
        'partitions_usage': partitions_usage,
        'cpu': cpus_usage,
        'io': io,
        'network': network,
    }
    send_request(data)
    wd.ping()

    sleep_time = CHECK_INTERVAL - (time.monotonic() - start_time)
