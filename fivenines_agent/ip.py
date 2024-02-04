import os
import sys
import traceback

from fivenines_agent.env import debug_mode

def ipv4():
  try:
    with os.popen('curl -4 -s https://ip.fivenines.io', 'r') as f:
      result = f.read().rstrip('\n')
    if debug_mode():
      print(f'ipv4: {repr(result)}')

    if result != '':
      return result
  except Exception as e:
    print('IPv4 address could not be retrieved')
    print(e, file=sys.stderr)
    print(traceback.print_exc(), file=sys.stderr)

def ipv6():
  try:
    with os.popen('curl -6 -s https://ip.fivenines.io', 'r') as f:
      result = f.read().rstrip('\n')
    if debug_mode():
      print(f'ipv6: {repr(result)}')

    if result != '':
      return result
  except Exception as e:
    print('IPv6 address could not be retrieved')
    print(e, file=sys.stderr)
    print(traceback.print_exc(), file=sys.stderr)
