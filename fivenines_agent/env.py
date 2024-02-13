import os

def api_url():
  return os.environ.get('API_URL', 'api.fivenines.io')

def debug_mode():
  return os.environ.get('DEBUG_MODE') == 'true'
