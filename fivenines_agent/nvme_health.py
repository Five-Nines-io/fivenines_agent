import subprocess
import json
import os
import re
import shutil
import time

from fivenines_agent.env import debug_mode

_NVME_CTRL_RE   = re.compile(r'^nvme(\d+)$')          # -> controller  number
_NVME_NS_RE     = re.compile(r'^nvme(\d+)n(\d+)$')    # -> controller, namespace

_nvme_cache = {
    "timestamp": 0,
    "data": []
}

def nvme_cli_available() -> bool:
    return shutil.which("nvme") is not None

def _discover_nvme_nodes():
    """
    Yield dicts:
      {"path": "/dev/nvme0",   "type": "controller", "ctrl": 0}
      {"path": "/dev/nvme0n1", "type": "namespace",  "ctrl": 0, "ns": 1}
    """
    for entry in os.listdir("/dev"):
        m_ctrl = _NVME_CTRL_RE.match(entry)
        m_ns   = _NVME_NS_RE.match(entry)
        if m_ctrl:
            yield {"path": f"/dev/{entry}", "type": "controller",
                   "ctrl": int(m_ctrl.group(1))}
        elif m_ns:
            yield {"path": f"/dev/{entry}", "type": "namespace",
                   "ctrl": int(m_ns.group(1)), "ns": int(m_ns.group(2))}


def list_nvme_devices():
    """Return the discovered devices."""
    devices = list(_discover_nvme_nodes())
    return sorted(devices,
                  key=lambda d: (d["ctrl"], d.get("ns", -1)))   # namespaces after their ctrl


def _run_nvme(cmd, device):
    """Run nvme‑cli and return parsed JSON or raise."""
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def get_nvme_info(dev_dict):
    """Fetch SMART/health data for a controller or namespace."""
    try:
        if dev_dict["type"] == "controller":
            raw = _run_nvme(
                ["nvme", "smart-log", dev_dict["path"], "-o", "json"],
                dev_dict["path"]
            )

        else:  # namespace
            ctrl_path = f"/dev/nvme{dev_dict['ctrl']}"
            nsid      = dev_dict["ns"]
            # “smart-log --namespace-id=<id> <ctrl>” works everywhere ns‑SMART is supported
            raw = _run_nvme(
                ["nvme", "smart-log", f"--namespace-id={nsid}",
                 ctrl_path, "-o", "json"],
                dev_dict["path"]
            )

        return {
            "device": dev_dict["path"],
            "status": "ok",
            "temperature": raw.get("temperature") - 273.15, # convert to celsius
            "percentage_used": raw.get("percentage_used"),
            "available_spare": raw.get("available_spare"),
            "media_errors": raw.get("media_errors"),
            "unsafe_shutdowns": raw.get("unsafe_shutdowns"),
            "power_on_hours": raw.get("power_on_hours"),
            "critical_warning": raw.get("critical_warning"),
            "data_units_written": raw.get("data_units_written"),
            "data_units_read": raw.get("data_units_read"),
        }

    except subprocess.CalledProcessError as e:
        return {"device": dev_dict["path"], "status": "error",
                "error": e.stderr.strip()}
    except (json.JSONDecodeError, ValueError):
        return {"device": dev_dict["path"], "status": "error",
                "error": "Invalid JSON from nvme-cli"}
    except Exception as e:
        return {"device": dev_dict["path"], "status": "error",
                "error": str(e)}


def nvme_health():
    """
    Collect health info for all NVMe controllers and namespaces.
    Cached for 60 s.
    """
    global _nvme_cache
    now = time.time()

    if now - _nvme_cache["timestamp"] < 60:
        return _nvme_cache["data"]

    if not nvme_cli_available():
        if debug_mode:
            print("nvme-cli not installed")
        data = []
    else:
        devices = list_nvme_devices()
        if not devices:
            if debug_mode:
                print("No NVMe devices found")
            data = []
        else:
            data = [get_nvme_info(dev) for dev in devices]

    _nvme_cache["timestamp"] = now
    _nvme_cache["data"] = data
    return data
