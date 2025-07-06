import psutil
from fivenines_agent.debug import debug

@debug('load_average')
def load_average():
    return psutil.getloadavg()
