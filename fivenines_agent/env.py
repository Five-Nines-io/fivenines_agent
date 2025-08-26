import os
import sys

def api_url():
  return os.environ.get('API_URL', 'api.fivenines.io')

def config_dir():
  return os.environ.get('CONFIG_DIR', '/etc/fivenines_agent')

def env_file():
  return os.path.join(config_dir(), '.env')

def dry_run():
  return os.environ.get('DRY_RUN') == 'true' or '--dry-run' in sys.argv

def log_level():
  if dry_run():
    return 'debug'
  else:
    return os.environ.get('LOG_LEVEL', 'info')
