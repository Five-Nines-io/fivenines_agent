import os
import sys
import re
import socket
import traceback

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

@debug('redis_metrics')
def redis_metrics(port=6379, password=None):
    auth_prefix = ''
    if password:
      auth_prefix = f'AUTH {password}\n'

    try:

      # Use create_connection for better address handling (IPv4/IPv6)
      s = socket.create_connection(('localhost', int(port)), timeout=5)

      commands = []
      if password:
          commands.append(f'AUTH {password}')
      commands.append('INFO')
      commands.append('QUIT')

      # Use CRLF for Redis protocol
      full_command = '\r\n'.join(commands) + '\r\n'
      s.sendall(full_command.encode())

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
              k, v = v.split('=')
              metrics[key][k] = int(v.strip())
          else:
            metrics[key] = int(value.strip())

      return metrics

    except Exception as e:
      log(f"Error collecting Redis metrics: {e}", 'error')
