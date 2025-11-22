import os
import sys
import traceback

from fivenines_agent.debug import debug

METRICS = '\|'.join([
  'redis_version',
  'connected_clients',
  'maxclients',
  '^db[0-9]'
])

@debug('redis_metrics')
def redis_metrics(port=6379, password=None):
    auth_prefix = ''
    if password:
      auth_prefix = f'AUTH {password}\n'

    try:
      with os.popen(f'echo "{auth_prefix}INFO\nQUIT" | curl -s telnet://localhost:{port} | grep -e "{METRICS}"', 'r') as f:
        results = list(filter(None, f.read().rstrip('\n').split('\n')))

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
