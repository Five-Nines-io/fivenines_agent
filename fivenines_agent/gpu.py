"""NVIDIA GPU metrics collector using pynvml (optional dependency)."""

from fivenines_agent.debug import debug, log


try:
    import pynvml

    HAS_NVML = True
except ImportError:
    HAS_NVML = False


def _safe(fn, *args):
    """Call an NVML function, returning None on any error."""
    try:
        return fn(*args)
    except Exception:
        return None


def _collect_processes(handle):
    """Collect both compute and graphics processes for a GPU handle."""
    processes = []
    for getter in (
        pynvml.nvmlDeviceGetComputeRunningProcesses,
        pynvml.nvmlDeviceGetGraphicsRunningProcesses,
    ):
        try:
            for proc in getter(handle):
                processes.append(
                    {
                        "pid": proc.pid,
                        "memory_used": proc.usedGpuMemory,
                    }
                )
        except Exception:
            pass
    return processes


@debug("nvidia_gpu")
def gpu_metrics():
    """Collect metrics for all NVIDIA GPUs."""
    if not HAS_NVML:
        return None

    try:
        pynvml.nvmlInit()
    except Exception:
        return None

    try:
        count = pynvml.nvmlDeviceGetCount()
        gpus = []
        for i in range(count):
            try:
                handle = pynvml.nvmlDeviceGetHandleByIndex(i)

                name = _safe(pynvml.nvmlDeviceGetName, handle)
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")

                utilization = _safe(pynvml.nvmlDeviceGetUtilizationRates, handle)
                mem_info = _safe(pynvml.nvmlDeviceGetMemoryInfo, handle)

                gpus.append(
                    {
                        "index": i,
                        "name": name,
                        "temperature": _safe(
                            pynvml.nvmlDeviceGetTemperature,
                            handle,
                            pynvml.NVML_TEMPERATURE_GPU,
                        ),
                        "fan_speed": _safe(pynvml.nvmlDeviceGetFanSpeed, handle),
                        "power_draw": _safe(pynvml.nvmlDeviceGetPowerUsage, handle),
                        "power_limit": _safe(
                            pynvml.nvmlDeviceGetPowerManagementLimit, handle
                        ),
                        "utilization_gpu": (utilization.gpu if utilization else None),
                        "utilization_memory": (
                            utilization.memory if utilization else None
                        ),
                        "memory_used": (mem_info.used if mem_info else None),
                        "memory_total": (mem_info.total if mem_info else None),
                        "memory_free": (mem_info.free if mem_info else None),
                        "clock_sm": _safe(
                            pynvml.nvmlDeviceGetClockInfo,
                            handle,
                            pynvml.NVML_CLOCK_SM,
                        ),
                        "clock_mem": _safe(
                            pynvml.nvmlDeviceGetClockInfo,
                            handle,
                            pynvml.NVML_CLOCK_MEM,
                        ),
                        "processes": _collect_processes(handle),
                    }
                )
            except Exception:
                log(f"gpu: error collecting GPU {i}", "error")
        return gpus
    except Exception:
        return None
    finally:
        pynvml.nvmlShutdown()
