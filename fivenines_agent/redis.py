import re
import socket

from fivenines_agent.debug import debug, log

METRICS_REGEX = '|'.join([
  'redis_version',
  'uptime_in_seconds',
  'blocked_clients',
  'connected_clients',
  'evicted_clients',
  'maxclients',
  'total_connections_received',
  'total_commands_processed',
  'evicted_keys',
  'expired_keys',
  '^db[0-9]'
])


def _resp_command(*args):
    """Encode a Redis command using the RESP binary-safe protocol.

    Length-prefixes each argument, making the encoding immune to CRLF
    injection regardless of argument content.
    """
    parts = [f"*{len(args)}\r\n"]
    for arg in args:
        encoded = str(arg).encode("utf-8")
        parts.append(f"${len(encoded)}\r\n{str(arg)}\r\n")
    return "".join(parts)


@debug('redis_metrics')
def redis_metrics(port=6379, password=None):
    try:
        s = socket.create_connection(('localhost', int(port)), timeout=5)

        payload = ""
        if password:
            payload += _resp_command("AUTH", password)
        payload += _resp_command("INFO")
        payload += _resp_command("QUIT")
        s.sendall(payload.encode("utf-8"))

        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()

        results = []
        for line in data.decode('utf-8', errors='ignore').split('\n'):
            line = line.strip()
            if not line:
                continue
            if re.search(METRICS_REGEX, line):
                results.append(line)

        metrics = {}

        if len(results) > 0:
            for result in results:
                key, value = result.split(':')
                if key == 'redis_version':
                    metrics[key] = value.strip()
                elif key.startswith('db'):
                    metrics[key] = {}
                    values = value.split(',')
                    for v in values:
                        k, raw_val = v.split('=')
                        metrics[key][k.strip()] = float(raw_val.strip())
                else:
                    metrics[key] = float(value.strip())

        return metrics

    except Exception as e:
        log(f"Error collecting Redis metrics: {e}", 'error')
