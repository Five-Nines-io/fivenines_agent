import os
import sys

def api_url():
  return os.environ.get('API_URL', 'api.fivenines.io')

def dry_run():
  return os.environ.get('DRY_RUN') == 'true' or '--dry-run' in sys.argv

def log_level():
  if dry_run():
    return 'debug'
  else:
    return os.environ.get('LOG_LEVEL', 'info')
