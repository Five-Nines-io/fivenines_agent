#!/usr/bin/env python3
"""Minimal mock API server for CI distro testing.

Returns a valid config response so the agent's --dry-run mode can
complete without needing a real API connection or valid token.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

CONFIG_RESPONSE = json.dumps({
    "config": {
        "enabled": True,
        "interval": 60,
        "cpu": True,
        "memory": True,
        "load_average": True,
        "io": True,
        "network": True,
        "partitions": True,
        "files": True,
        "ports": False,
        "processes": False,
        "temperatures": False,
        "fans": False,
        "request_options": {"timeout": 5, "retry": 3, "retry_interval": 5},
    }
}).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Read and discard request body
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(CONFIG_RESPONSE)

    def log_message(self, format, *args):
        pass  # Suppress request logs


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"Mock API server listening on 127.0.0.1:{port}")
    sys.stdout.flush()
    server.serve_forever()
