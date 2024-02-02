import http
import sys
import traceback

def ipv4():
  try:
    conn = http.client.HTTPSConnection('ip.fivenines.io', timeout=5)
    res = conn.request('GET', '/')
    res = conn.getresponse()
    body = res.read().decode("utf-8")
    return body

  except Exception as e:
    print(e, file=sys.stderr)
    print(traceback.print_exc(), file=sys.stderr)
