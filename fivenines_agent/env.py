import os
import sys

def api_url():
  return os.environ.get('API_URL', 'api.fivenines.io')

def debug_mode():
  return os.environ.get('DEBUG_MODE') == 'true' or '--debug' in sys.argv

def dry_run():
  return os.environ.get('DRY_RUN') == 'true' or '--dry-run' in sys.argv
