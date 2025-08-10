import psutil
from fivenines_agent.debug import debug

@debug('temperatures')
def temperatures():
  return psutil.sensors_temperatures()
