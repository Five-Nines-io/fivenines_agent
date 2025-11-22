import os
import sys
import traceback
import requests

from fivenines_agent.debug import debug, log


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

@debug('nginx_metrics')
def nginx_metrics(status_page_url='http://127.0.0.1:8080/nginx_status'):
    try:
      response = requests.get(status_page_url)
      if response.status_code != 200:
        return None

      results = response.text.splitlines()
      header_version = response.headers['Server']
      if header_version:
        version = header_version.split('/')[1]
      else:
        version = None

      metrics = { 'nginx_version': version }

      if len(results) > 0:
        metrics['active_connections'] = int(results[0].split(':')[1].strip())
        metrics['reading_connections'] = int(results[3].split(' ')[1])
        metrics['writing_connections'] = int(results[3].split(' ')[3])
        metrics['waiting_connections'] = int(results[3].split(' ')[5])

      return metrics

    except Exception as e:
      log(f"Error collecting NGINX metrics: {e}", 'error')
