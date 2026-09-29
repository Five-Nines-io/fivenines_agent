#!/usr/bin/env python3
"""Mock fivenines API for footprint benchmarking.

Answers every POST with a config, and saves each decompressed payload so the
Python and Go agents' output can be diffed.

usage: mock.py PORT OUT_DIR PROFILE INTERVAL
  PROFILE core -> the core collectors only
  PROFILE procs -> core + processes
  PROFILE docker -> core + processes + docker (needs DOCKER_SOCKET, see mock_docker.py)
  PROFILE full -> the agent's own --dry-run config (everything it can run)
"""

import gzip
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port, out_dir, profile, interval = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
os.makedirs(out_dir, exist_ok=True)

CORE = {
    "enabled": True,
    "interval": interval,
    "request_options": {"timeout": 5, "retry": 3, "retry_interval": 5},
    "cpu": True,
    "memory": True,
    "network": True,
    "partitions": True,
    "io": True,
}

if profile == "full":
    import ast

    tree = ast.parse(open(os.path.join(os.environ["AGENT_SRC"], "fivenines_agent/agent.py")).read())
    _DRY_RUN_CONFIG = next(
        ast.literal_eval(n.value) for n in tree.body
        if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "_DRY_RUN_CONFIG"
    )

    CONFIG = dict(_DRY_RUN_CONFIG, interval=interval)
elif profile == "procs":
    CONFIG = dict(CORE, processes=True)
elif profile == "docker":
    # core + processes + docker against bench/mock_docker.py's socket
    CONFIG = dict(CORE, processes=True, docker={"socket_url": "unix://" + os.environ["DOCKER_SOCKET"]})
else:
    CONFIG = CORE

BODY = json.dumps({"config": CONFIG}).encode()
count = 0


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, like the real API

    def do_POST(self):
        global count
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.headers.get("Content-Encoding") == "gzip":
            raw = gzip.decompress(raw)
        count += 1
        name = self.path.strip("/").replace("/", "_")
        with open(os.path.join(out_dir, f"{count:03d}-{name}.json"), "wb") as f:
            f.write(raw)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", int(port)), Handler).serve_forever()
