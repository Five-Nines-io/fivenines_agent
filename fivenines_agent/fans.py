import psutil
from fivenines_agent.debug import debug

@debug('fans')
def fans():
    return psutil.sensors_fans()
