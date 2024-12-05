import sys
import traceback
import socket
import ssl
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
            except OSError:
                if self.sock:
                    self.sock.close()
                raise ConnectionError(
                    f"Could not connect to {self.host} on port {self.port} with family {'IPv6' if self.ipv6 else 'IPv4'}"
                )

def get_ip(ipv6=False):
    try:
        context = ssl.create_default_context()

        conn = CustomHTTPSConnection("ip.fivenines.io", ipv6=ipv6, context=context)
        conn.request("GET", "")
        response = conn.getresponse()
        body = response.read().decode("utf-8")

        if debug_mode():
            print(f"Status: {response.status}, Reason: {response.reason}")
            print(body)

        if response.status == 200:
            return body.strip()
    except Exception as e:
        print(e, file=sys.stderr)
        print(traceback.print_exc(), file=sys.stderr)
    finally:
        if conn:
            conn.close()
