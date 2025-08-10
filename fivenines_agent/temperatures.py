import psutil
from fivenines_agent.debug import debug

@debug('temperatures')
def temperatures():
  if not hasattr(psutil, "sensors_temperatures"):
    return {}

  return psutil.sensors_temperatures()
