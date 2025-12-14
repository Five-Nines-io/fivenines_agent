import os

from fivenines_agent.cli import get_args


def api_url():
  return os.environ.get('API_URL', 'api.fivenines.io')

def config_dir():
  return os.environ.get('CONFIG_DIR', '/etc/fivenines_agent')

def env_file():
  return os.path.join(config_dir(), '.env')

def dry_run():
  # Check environment variable first
  if os.environ.get('DRY_RUN') == 'true':
    return True
  # Check parsed args
  args = get_args()
  return args is not None and args.dry_run

def log_level():
  if dry_run():
    return 'debug'
  else:
    return os.environ.get('LOG_LEVEL', 'info')
