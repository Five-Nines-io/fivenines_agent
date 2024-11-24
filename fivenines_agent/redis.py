import os
import sys
import traceback

METRICS = '\|'.join([
  'redis_version',
  'connected_clients',
  'maxclients',
  '^db[0-9]'
])

def redis_metrics(port=6379, password=None):
    redis_installed = False
    if os.system('which redis-server > /dev/null') == 0:
      redis_installed = True

    if not redis_installed:
      return None

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
      print(e, file=sys.stderr)
      print(traceback.print_exc(), file=sys.stderr)
