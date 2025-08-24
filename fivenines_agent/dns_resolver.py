import dns.resolver, dns.exception
from fivenines_agent.debug import log

class DNSResolver:
    def __init__(self, host):
        self.host = host

    def resolve(self, record_type, timeout=5.0):
        try:
            return dns.resolver.resolve(self.host, record_type, lifetime=timeout)
        except dns.exception.DNSException as e:
            log(f"DNS error resolving {self.host} {record_type}: {e}")
            return None
