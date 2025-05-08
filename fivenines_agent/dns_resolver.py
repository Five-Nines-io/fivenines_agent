import dns.resolver, dns.exception

class DNSResolver:
    def __init__(self, host):
        self.host = host

    def resolve(self, record_type, timeout=5.0):
        try:
            return dns.resolver.resolve(self.host, record_type, lifetime=timeout)
        except dns.exception.DNSException as e:
            print(f"DNS error resolving {self.host} {record_type}: {e}")
            return None
