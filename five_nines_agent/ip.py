import os
import sys
import traceback
import systemd_watchdog as wd

def ipv4():
  try:
    return os.popen('curl -4 -s https://ip.fivenines.io').read().rstrip('\n')
  except Exception as e:
    print('IPv4 address could not be retrieved')
    print(e, file=sys.stderr)
    print(traceback.print_exc(), file=sys.stderr)
    return '-'
