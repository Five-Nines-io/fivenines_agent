import psutil
from fivenines_agent.debug import debug

@debug('memory')
def memory():
    return psutil.virtual_memory()._asdict()

@debug('swap')
def swap():
    return psutil.swap_memory()._asdict()
