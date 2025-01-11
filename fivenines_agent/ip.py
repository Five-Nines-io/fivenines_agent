import sys
import traceback
import socket
import ssl
import certifi
import http.client

from fivenines_agent.env import debug_mode
class CustomHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port=None, ipv6=False, timeout=5, **kwargs):
        super().__init__(host, port, timeout=timeout, **kwargs)
        self.ipv6 = ipv6
        self.timeout = timeout

    def connect(self):
        family = socket.AF_INET6 if self.ipv6 else socket.AF_INET

        for res in socket.getaddrinfo(self.host, self.port, family, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                self.sock = socket.socket(af, socktype, proto)
                self.sock.connect(sa)

                self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)
                return
            except socket.gaierror as e:
                raise ConnectionError(f"DNS resolution failed for {self.host}: {e}")
            except OSError as e:
                if self.sock:
                    self.sock.close()
                raise ConnectionError(
                    f"Could not connect to {self.host} on port {self.port} with family {'IPv6' if self.ipv6 else 'IPv4'}: {e}"
                )

def get_ip(ipv6=False):
    try:
        ssl_context = ssl.create_default_context(cafile=certifi.where())

        conn = CustomHTTPSConnection("ip.fivenines.io", ipv6=ipv6, context=ssl_context)
        conn.request("GET", "")
        response = conn.getresponse()
        body = response.read().decode("utf-8")

        if debug_mode():
            print(f"Status: {response.status}, Reason: {response.reason}", file=sys.stderr)
            print(f"Response body: {body}", file=sys.stderr)

        if response.status == 200:
            return body.strip()

        return None
    except ConnectionError as e:
        # Log the error and optionally retry or handle IPv4 fallback
        print(f"Unexpected error occurred: {e}", file=sys.stderr)
        return None

    except Exception as e:
        print(e, file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return None
    finally:
        if conn:
            conn.close()
