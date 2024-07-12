import sys
import traceback
import socket
import requests.packages.urllib3.util.connection

from fivenines_agent.env import debug_mode

def set_ip_version(ip_version: int = 6):
    if ip_version == 4:
        def allowed_gai_family():
            return socket.AF_INET

    elif ip_version == 6:
        def allowed_gai_family():
            if requests.packages.urllib3.util.connection.HAS_IPV6:
                return socket.AF_INET6
            return socket.AF_INET

    else:
        return False

    requests.packages.urllib3.util.connection.allowed_gai_family = allowed_gai_family
    return True

def get_ip(version: int = 6):
  set_ip_version(version)

  try:
    res = requests.get("https://ip.fivenines.io")
    result = res.text.strip()
    if debug_mode():
      print(f'ipv4: {repr(result)}')

    if result != '':
      return result
  except Exception as e:
    print(e, file=sys.stderr)
    print(traceback.print_exc(), file=sys.stderr)
