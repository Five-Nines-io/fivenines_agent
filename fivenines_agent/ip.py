import sys
import traceback
import socket
import ssl
import certifi
import time
import http.client
from fivenines_agent.dns_resolver import DNSResolver
from fivenines_agent.debug import debug, log

_ip_v4_cache = { "timestamp": 0, "ip": None }
_ip_v6_cache = { "timestamp": 0, "ip": None }

class CustomHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port=None, ipv6=False, timeout=5, **kwargs):
        super().__init__(host, port, timeout=timeout, **kwargs)
        self.ipv6 = ipv6
        self.timeout = timeout

    def connect(self):
        resolver = DNSResolver(self.host)
        record_type = "AAAA" if self.ipv6 else "A"
        try:
            answers = resolver.resolve(record_type)
            if not answers:
                raise ConnectionError(f"No DNS records found for {self.host} ({record_type})")
        except Exception as e:
            raise ConnectionError(f"DNS resolution failed for {self.host}: {e}")

        for rdata in answers:
            ip = rdata.address
            af = socket.AF_INET6 if self.ipv6 else socket.AF_INET
            try:
                self.sock = socket.socket(af, socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                self.sock.connect((ip, self.port))
                self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)
                return
            except OSError as e:
                if self.sock:
                    self.sock.close()
                log(f"Could not connect to {ip}: {e}", 'error')
                continue  # Try next IP

        raise ConnectionError(
            f"Could not connect to {self.host} on port {self.port} with family {'IPv6' if self.ipv6 else 'IPv4'}"
        )

@debug('get_ip')
def get_ip(ipv6=False):
    global _ip_v4_cache, _ip_v6_cache
    now = time.time()

    if ipv6:
        if now - _ip_v6_cache["timestamp"] < 60:
            return _ip_v6_cache["ip"]
    else:
        if now - _ip_v4_cache["timestamp"] < 60:
            return _ip_v4_cache["ip"]

    try:
        ssl_context = ssl.create_default_context(cafile=certifi.where())

        conn = CustomHTTPSConnection("ip.fivenines.io", ipv6=ipv6, context=ssl_context)
        conn.request("GET", "")
        response = conn.getresponse()
        body = response.read().decode("utf-8")

        log(f"Status: {response.status}, Reason: {response.reason}", 'debug')
        log(f"Response body: {body}", 'debug')

        if response.status == 200:
            return body.strip()

        return None
    except ConnectionError as e:
        # Log the error and optionally retry or handle IPv4 fallback
        log(f"Unexpected error occurred: {e}", 'error')
        return None

    except Exception as e:
        log(f"Unexpected error occurred: {e}", 'error')
        traceback.print_exc(file=sys.stderr)
        return None
    finally:
        if conn:
            conn.close()
