import psutil

def io():
  io = []
  for k, v in psutil.disk_io_counters(perdisk=True).items():
    io.append({ k: v._asdict()})

  return io
