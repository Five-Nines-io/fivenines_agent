#!/usr/bin/env python3
"""Mock Docker Engine API on a unix socket, for the docker collector ports.

usage: mock_docker.py SOCKET_PATH [N_CONTAINERS] [FAULT]

FAULT injects one failure, to check each port against docker.py's contract:
  vanish   -- container #1 answers 404 on inspect (docker.py: skip it)
  error500 -- container #0 answers 500 on stats (docker.py: docker = null,
              because docker-py's APIError IS a requests RequestException)
  newstate -- container #2 reports a state this API version does not define,
              in the list and in inspect (docker.py: passes the string through)
Requests for an API version above API_VERSION get dockerd's 400, so a client
that does not negotiate the version fails here as it would on an older daemon.

Serves the calls the agent's docker collector makes -- /_ping, /version,
/containers/json, /containers/{id}/json, /images/{id}/json and
/containers/{id}/stats -- with response bodies shaped and sized like a real
daemon's (a full inspect is several KB). CPU, memory, block-I/O and network
counters advance with wall-clock time so percentages are non-zero. The
container set covers every branch of docker.py: running with and without a
HEALTHCHECK, exited (one OOM-killed), created (Go zero timestamps),
restarting, and an image whose only tag is "<none>:<none>", which docker-py's
Image.tags filters out.
"""

import hashlib
import json
import os
import re
import socketserver
import sys
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import unquote, urlparse

SOCKET = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 40
FAULT = sys.argv[3] if len(sys.argv) > 3 else ""
T0 = time.time()
NCPU = 16
API_VERSION = os.environ.get("MOCK_API_VERSION", "1.51")  # 1.41 = Debian 12 docker.io 20.10
ZERO = "0001-01-01T00:00:00Z"
# system_cpu_usage is the host's total CPU time in ns: a 16-core host up 30
# days is ~4.1e16 -- past 2**53, so a float64 cannot hold it exactly.
SYS_CPU0 = 30 * 86400 * NCPU * 10**9


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


IMAGES = []
for i, (repo, tags) in enumerate([
    ("nginx", ["nginx:1.27", "nginx:latest"]),
    ("postgres", ["postgres:16"]),
    ("redis", ["redis:7-alpine"]),
    ("app", ["registry.example.com/acme/app:2026.09.1"]),
    ("worker", ["registry.example.com/acme/worker:2026.09.1"]),
    ("dangling", ["<none>:<none>"]),
    ("untagged", None),
    ("grafana", ["grafana/grafana:11.2.0"]),
]):
    iid = "sha256:" + sha("image" + repo)
    IMAGES.append({
        "Id": iid,
        "RepoTags": tags,
        "RepoDigests": [] if repo in ("dangling", "untagged") else [f"{repo}@sha256:{sha('digest' + repo)}"],
        "Parent": "",
        "Comment": "buildkit.dockerfile.v0",
        "Created": "2026-09-01T10:00:00.000000000Z",
        "DockerVersion": "",
        "Author": "",
        "Config": {
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", f"{repo.upper()}_VERSION=1.0.{i}"],
            "Cmd": [repo],
            "WorkingDir": "/",
            "Labels": {"org.opencontainers.image.source": f"https://github.com/example/{repo}"},
        },
        "Architecture": "amd64",
        "Os": "linux",
        "Size": 50_000_000 + i * 7_000_000,
        "GraphDriver": {"Name": "overlay2", "Data": {"MergedDir": f"/var/lib/docker/overlay2/{sha(repo)}/merged"}},
        "RootFS": {"Type": "layers", "Layers": ["sha256:" + sha(f"{repo}{n}") for n in range(6)]},
        "Metadata": {"LastTagTime": "0001-01-01T00:00:00Z"},
    })

CONTAINERS = []
for i in range(N):
    img = IMAGES[i % len(IMAGES)]
    name = f"stack-{img['Id'][7:13]}-{i}"
    cid = sha("container" + name)
    if i < int(N * 0.75):
        state, exit_code, oom, started, finished = "running", 0, False, "2026-09-28T08:00:00.123456789Z", ZERO
    elif i < int(N * 0.9):
        state, exit_code, oom = "exited", [0, 1, 137][i % 3], i % 3 == 2
        started, finished = "2026-09-27T08:00:00.1Z", "2026-09-28T02:13:14.5Z"
    elif i < N - 1:
        state, exit_code, oom, started, finished = "created", 0, False, ZERO, ZERO
    else:
        state, exit_code, oom, started, finished = "restarting", 1, False, "2026-09-29T07:00:00Z", "2026-09-29T07:00:05Z"
    health = [None, "healthy", "unhealthy", "starting"][i % 4] if state == "running" else None
    config_image = img["RepoTags"][0] if img["RepoTags"] and img["RepoTags"][0] != "<none>:<none>" else img["Id"]
    CONTAINERS.append({
        "i": i, "id": cid, "name": name, "image": img, "config_image": config_image, "state": state,
        "exit_code": exit_code, "oom": oom, "started": started, "finished": finished, "health": health,
        "restart_count": 5 if state == "restarting" else i % 3,
    })
BY_ID = {c["id"]: c for c in CONTAINERS}
IMAGES_BY_ID = {img["Id"]: img for img in IMAGES}


def labels(c):
    return {
        "com.docker.compose.project": "stack",
        "com.docker.compose.service": c["name"].split("-")[0],
        "com.docker.compose.container-number": str(c["i"]),
        "com.docker.compose.oneoff": "False",
        "com.docker.compose.version": "2.29.2",
        "com.docker.compose.config-hash": sha("cfg" + c["name"]),
        "com.docker.compose.depends_on": "",
        "com.docker.compose.image": c["image"]["Id"],
        "com.docker.compose.project.config_files": "/srv/stack/compose.yaml",
        "com.docker.compose.project.working_dir": "/srv/stack",
    }


def summary(c):
    return {
        "Id": c["id"], "Names": ["/" + c["name"]], "Image": c["config_image"], "ImageID": c["image"]["Id"],
        "Command": "/docker-entrypoint.sh run", "Created": 1759000000 + c["i"], "Ports": [],
        "Labels": labels(c), "State": "checkpointed" if FAULT == "newstate" and c["i"] == 2 else c["state"],
        "Status": c["state"].capitalize(),
        "HostConfig": {"NetworkMode": "stack_default"},
        "NetworkSettings": {"Networks": {"stack_default": {"NetworkID": sha("net"), "EndpointID": sha("ep" + c["id"]),
                                                          "Gateway": "172.18.0.1", "IPAddress": f"172.18.0.{c['i'] + 2}",
                                                          "IPPrefixLen": 16, "MacAddress": "02:42:ac:12:00:02"}}},
        "Mounts": [{"Type": "volume", "Name": "stack_data", "Source": "/var/lib/docker/volumes/stack_data/_data",
                    "Destination": "/data", "Driver": "local", "Mode": "z", "RW": True, "Propagation": ""}],
    }


def inspect(c):
    running = c["state"] in ("running", "restarting")
    state = {
        "Status": c["state"], "Running": running, "Paused": False, "Restarting": c["state"] == "restarting",
        "OOMKilled": c["oom"], "Dead": False, "Pid": 4000 + c["i"] if running else 0, "ExitCode": c["exit_code"],
        "Error": "", "StartedAt": c["started"], "FinishedAt": c["finished"],
    }
    if c["health"]:
        state["Health"] = {"Status": c["health"], "FailingStreak": 3 if c["health"] == "unhealthy" else 0,
                           "Log": [{"Start": "2026-09-29T08:00:00Z", "End": "2026-09-29T08:00:01Z",
                                    "ExitCode": 0, "Output": "ok\n"}] * 5}
    return {
        "Id": c["id"], "Created": "2026-09-01T10:00:00.000000000Z", "Path": "/docker-entrypoint.sh",
        "Args": ["run", "--config", "/etc/app/config.yaml"], "State": state, "Image": c["image"]["Id"],
        "ResolvConfPath": f"/var/lib/docker/containers/{c['id']}/resolv.conf",
        "HostnamePath": f"/var/lib/docker/containers/{c['id']}/hostname",
        "HostsPath": f"/var/lib/docker/containers/{c['id']}/hosts",
        "LogPath": f"/var/lib/docker/containers/{c['id']}/{c['id']}-json.log",
        "Name": "/" + c["name"], "RestartCount": c["restart_count"], "Driver": "overlay2", "Platform": "linux",
        "MountLabel": "", "ProcessLabel": "", "AppArmorProfile": "docker-default", "ExecIDs": None,
        "HostConfig": {
            "Binds": None, "ContainerIDFile": "", "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m"}},
            "NetworkMode": "stack_default", "PortBindings": {}, "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
            "AutoRemove": False, "VolumeDriver": "", "VolumesFrom": None, "ConsoleSize": [0, 0], "CapAdd": None,
            "CapDrop": None, "CgroupnsMode": "private", "Dns": [], "DnsOptions": [], "DnsSearch": [], "ExtraHosts": [],
            "GroupAdd": None, "IpcMode": "private", "Cgroup": "", "Links": None, "OomScoreAdj": 0, "PidMode": "",
            "Privileged": False, "PublishAllPorts": False, "ReadonlyRootfs": False, "SecurityOpt": None, "UTSMode": "",
            "UsernsMode": "", "ShmSize": 67108864, "Runtime": "runc", "Isolation": "", "CpuShares": 0, "Memory": 0,
            "NanoCpus": 0, "CgroupParent": "", "BlkioWeight": 0, "BlkioWeightDevice": None, "BlkioDeviceReadBps": None,
            "BlkioDeviceWriteBps": None, "BlkioDeviceReadIOps": None, "BlkioDeviceWriteIOps": None, "CpuPeriod": 0,
            "CpuQuota": 0, "CpuRealtimePeriod": 0, "CpuRealtimeRuntime": 0, "CpusetCpus": "", "CpusetMems": "",
            "Devices": None, "DeviceCgroupRules": None, "DeviceRequests": None, "MemoryReservation": 0, "MemorySwap": 0,
            "MemorySwappiness": None, "OomKillDisable": None, "PidsLimit": None, "Ulimits": None, "CpuCount": 0,
            "CpuPercent": 0, "IOMaximumIOps": 0, "IOMaximumBandwidth": 0,
            "MaskedPaths": ["/proc/asound", "/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
                            "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi", "/sys/firmware",
                            "/sys/devices/virtual/powercap"],
            "ReadonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"],
        },
        "GraphDriver": {"Name": "overlay2", "Data": {
            "LowerDir": ":".join(f"/var/lib/docker/overlay2/{sha(c['id'] + str(n))}/diff" for n in range(6)),
            "MergedDir": f"/var/lib/docker/overlay2/{sha(c['id'])}/merged",
            "UpperDir": f"/var/lib/docker/overlay2/{sha(c['id'])}/diff",
            "WorkDir": f"/var/lib/docker/overlay2/{sha(c['id'])}/work"}},
        "Mounts": summary(c)["Mounts"],
        "Config": {
            "Hostname": c["id"][:12], "Domainname": "", "User": "", "AttachStdin": False, "AttachStdout": True,
            "AttachStderr": True, "ExposedPorts": {"8080/tcp": {}}, "Tty": False, "OpenStdin": False, "StdinOnce": False,
            "Env": [f"VAR_{n}=value-{n}-{c['i']}" for n in range(12)] + ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "Cmd": ["run"], "Image": c["config_image"], "Volumes": {"/data": {}}, "WorkingDir": "/app",
            "Entrypoint": ["/docker-entrypoint.sh"], "OnBuild": None, "Labels": labels(c),
        },
        "NetworkSettings": {
            "Bridge": "", "SandboxID": sha("sb" + c["id"]), "SandboxKey": f"/var/run/docker/netns/{c['id'][:12]}",
            "Ports": {"8080/tcp": None}, "HairpinMode": False, "LinkLocalIPv6Address": "", "LinkLocalIPv6PrefixLen": 0,
            "SecondaryIPAddresses": None, "SecondaryIPv6Addresses": None, "EndpointID": "", "Gateway": "",
            "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "IPAddress": "", "IPPrefixLen": 0, "IPv6Gateway": "",
            "MacAddress": "", "Networks": summary(c)["NetworkSettings"]["Networks"],
        },
    }


def stats(c):
    t = time.time() - T0
    ns = int((T0 + t) * 1e9)
    rate = (c["i"] % 7 + 1) * 0.05  # CPU cores' worth of usage
    total = int(3e12 + c["i"] * 1e10 + rate * t * 1e9)
    usage = 200_000_000 + c["i"] * 3_000_000 + int(t * 1000) % 5_000_000
    mem_stats = {k: (hash(k) % 50_000_000) for k in (
        "anon", "file", "kernel", "kernel_stack", "pagetables", "sec_pagetables", "percpu", "sock", "vmalloc", "shmem",
        "zswap", "zswapped", "file_mapped", "file_dirty", "file_writeback", "swapcached", "anon_thp", "file_thp",
        "shmem_thp", "active_anon", "active_file", "inactive_anon", "slab_reclaimable", "slab_unreclaimable", "slab",
        "workingset_refault_anon", "workingset_refault_file", "workingset_activate_anon", "pgfault", "pgmajfault")}
    mem_stats["inactive_file"] = 40_000_000 + c["i"] * 100_000

    def cpu(at_ns, total_usage):
        return {"cpu_usage": {"total_usage": total_usage, "usage_in_kernelmode": total_usage * 3 // 10,
                              "usage_in_usermode": total_usage * 7 // 10},
                "system_cpu_usage": SYS_CPU0 + (at_ns - int(T0 * 1e9)) * NCPU, "online_cpus": NCPU,
                "throttling_data": {"periods": 0, "throttled_periods": 0, "throttled_time": 0}}

    return {
        "name": "/" + c["name"], "id": c["id"], "read": "2026-09-29T09:00:00.000000000Z",
        "preread": "0001-01-01T00:00:00Z",
        "pids_stats": {"current": 12 + c["i"] % 9, "limit": 38364},
        "blkio_stats": {"io_service_bytes_recursive": [
            {"major": 253, "minor": 0, "op": "read", "value": 10_000_000 + int(t * 1000) * c["i"]},
            {"major": 253, "minor": 0, "op": "write", "value": 5_000_000 + int(t * 500) * c["i"]}],
            "io_serviced_recursive": None, "io_queue_recursive": None, "io_service_time_recursive": None,
            "io_wait_time_recursive": None, "io_merged_recursive": None, "io_time_recursive": None,
            "sectors_recursive": None},
        "num_procs": 0, "storage_stats": {},
        "cpu_stats": cpu(ns, total),
        "precpu_stats": cpu(ns - 1_000_000_000, total - int(rate * 1e9)),
        "memory_stats": {"usage": usage, "stats": mem_stats, "limit": 67_000_000_000},
        "networks": {"eth0": {"rx_bytes": 1_000_000 + int(t * 2000), "rx_packets": 9000 + int(t * 10), "rx_errors": 0,
                              "rx_dropped": 0, "tx_bytes": 500_000 + int(t * 1000), "tx_packets": 4000 + int(t * 5),
                              "tx_errors": 0, "tx_dropped": 0}},
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, code, body, ctype="application/json"):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Api-Version", API_VERSION)
        self.send_header("Docker-Experimental", "false")
        self.send_header("Ostype", "linux")
        self.send_header("Server", "Docker/28.4.0 (linux)")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        raw_path = urlparse(self.path).path
        if os.environ.get("MOCK_LOG"):
            with open(os.environ["MOCK_LOG"], "a") as log:
                log.write(f"{self.command} {self.path}\n")
        v = re.match(r"^/v(\d+)\.(\d+)", raw_path)
        if v and (int(v[1]), int(v[2])) > tuple(map(int, API_VERSION.split("."))):
            return self.reply(400, {"message": f"client version {v[1]}.{v[2]} is too new. "
                                               f"Maximum supported API version is {API_VERSION}"})
        path = unquote(re.sub(r"^/v[0-9.]+", "", raw_path))
        if path == "/_ping":
            return self.reply(200, b"OK", "text/plain; charset=utf-8")
        if path == "/version":
            return self.reply(200, {"Version": "28.4.0", "ApiVersion": API_VERSION, "MinAPIVersion": "1.24",
                                    "Os": "linux", "Arch": "amd64", "KernelVersion": os.uname().release,
                                    "GoVersion": "go1.24.7", "GitCommit": "249d679"})
        if path == "/containers/json":
            return self.reply(200, [summary(c) for c in CONTAINERS])
        m = re.fullmatch(r"/containers/([0-9a-f]+)/(json|stats)", path)
        if m and m[1] in BY_ID:
            c = BY_ID[m[1]]
            if FAULT == "vanish" and c["i"] == 1:
                return self.reply(404, {"message": f"No such container: {c['id']}"})
            if m[2] == "json":
                body = inspect(c)
                if FAULT == "newstate" and c["i"] == 2:
                    body["State"]["Status"] = "checkpointed"
                return self.reply(200, body)
            if FAULT == "error500" and c["i"] == 0:
                return self.reply(500, {"message": "cgroup read failed"})
            return self.reply(200, stats(c))
        m = re.fullmatch(r"/images/(.+)/json", path)
        if m and m[1] in IMAGES_BY_ID:
            return self.reply(200, IMAGES_BY_ID[m[1]])
        return self.reply(404, {"message": f"no such object: {path}"})

    def log_message(self, *args):
        pass

    def address_string(self):
        return "unix"


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


if os.path.exists(SOCKET):
    os.unlink(SOCKET)
Server(SOCKET, Handler).serve_forever()
