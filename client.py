import sys
import traceback
import time
import json
import http.client
import systemd_watchdog
import psutil

INTERVAL = 5 # seconds
ROOT_PATH = '/opt/five_nines_client'

wd = systemd_watchdog.watchdog()

def token():
    try:
        f = open(f'{ROOT_PATH}/TOKEN')
        return f.read().strip('\n')
    except FileNotFoundError:
        wd.notify_error('TOKEN file is missing')
        sys.exit(2)

def version():
    f = open(f'{ROOT_PATH}/VERSION')
    return f.read().strip('\n')

def send_request(data):
    try:
        conn.request("POST", "", json.dumps(data), { 'Authorize': f'Bearer {token}' })
    except Exception as e:
        print(e, file=sys.stderr)
        print(traceback.print_exc(), file=sys.stderr)

token = token()
version = version()
print(f'Five nines client v{version} started')

conn = http.client.HTTPSConnection('api.five-nines.io', timeout=5)
wd.ready()

sleep_time = INTERVAL

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

    partitions = []
    disks = {}
    for _, v in enumerate(psutil.disk_partitions(all=False)):
        partitions.append(v._asdict())
        disks[v.mountpoint] = psutil.disk_usage(v.mountpoint)._asdict()

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
        'partitions': partitions,
        'cpu': cpus_usage,
        'io': io,
        'network': network,
        'disks': disks,
    }
    send_request(data)
    wd.ping()

    sleep_time = INTERVAL - (time.monotonic() - start_time)
