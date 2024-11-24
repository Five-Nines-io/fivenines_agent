import os
import sys
import traceback

# This function is used to get the metrics from the NGINX status page.
# Active connections: current active client connections
# Accepts: accepted client connections
# Handled: handled connections
# Requests: number of client requests
# Reading: connections where NGINX is reading request header
# Writing: connections where NGINX is writing the response back to the client
# Waiting: idle client connections waiting for a request
#
# Example output:
# Active connections: 1
# server accepts handled requests
#  5 5 5
# Reading: 0 Writing: 1 Waiting: 0

def nginx_metrics(status_page_url='http://127.0.0.1', status_page_port=8080):
    nginx_installed = False
    if os.system('which nginx > /dev/null') == 0:
      nginx_installed = True

    if not nginx_installed:
      return None

    version = os.popen('nginx -v 2>&1').read().strip().split('/')[1]

    try:
      with os.popen(f'curl -s {status_page_url}:{status_page_port}/nginx_status', 'r') as f:
        results = list(filter(None, f.read().rstrip('\n').split('\n')))

      metrics = { 'nginx_version': version }

      if len(results) > 0:
        metrics['active_connections'] = int(results[0].split(':')[1].strip())
        metrics['reading_connections'] = int(results[3].split(' ')[1])
        metrics['writing_connections'] = int(results[3].split(' ')[3])
        metrics['waiting_connections'] = int(results[3].split(' ')[5])

      return metrics

    except Exception as e:
      print(e, file=sys.stderr)
      print(traceback.print_exc(), file=sys.stderr)
