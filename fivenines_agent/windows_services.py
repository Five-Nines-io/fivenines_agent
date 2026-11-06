"""Windows services collector: the state and start type of every service.

The Windows counterpart of the systemd collector's per-unit health. One read
per tick through the Service Control Manager (pywin32's win32service, already a
dependency of the Windows build):

  EnumServicesStatusEx(SERVICE_WIN32, SERVICE_STATE_ALL)
      ONE call: every Win32 service's name, display name, type, state, process
      id and exit codes. Drivers are not listed.
  per service, OpenService(SERVICE_QUERY_CONFIG), then
      QueryServiceConfig                       -> start type
      QueryServiceConfig2(DELAYED_AUTO_START)  -> delayed automatic start
      QueryServiceConfig2W(TRIGGER_INFO)       -> trigger start, through ctypes:
                                                  pywin32 does not implement
                                                  that info level

The start type is read on every tick, uncached: an operator who disables a
service and stops it must not read as "automatic and stopped" until a cache
expires.

Payload (tests/fixtures/windows_services_contract_payload.json):

  {"services": [{"name": "EventLog", "display_name": "Windows Event Log",
                 "state": "running", "start_type": "automatic",
                 "delayed_auto_start": false, "trigger_start": false,
                 "pid": 1532, "exit_code": 0, "service_exit_code": 0}, ...]}

None off Windows, and while a read that outlived SCM_READ_TIMEOUT is still
blocked. A read that fails -- the Service Control Manager refused, the listing
failed, more than MAX_SERVICES services listed -- raises, and the dispatcher
reports null: never a partial list. The list itself is
what the agent's account can see -- EnumServicesStatusEx silently omits a
service whose security descriptor denies it SERVICE_QUERY_STATUS -- so a
service missing from one tick's list was not necessarily removed.
"""

from fivenines_agent.bounded import WorkerTimeout, call_bounded
from fivenines_agent.debug import debug, log
from fivenines_agent.env import is_windows
from fivenines_agent.scrub import log_safe, scrub_str

# winsvc.h
SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_ENUMERATE_SERVICE = 0x0004
SERVICE_QUERY_CONFIG = 0x0001
SERVICE_WIN32 = 0x00000030
SERVICE_STATE_ALL = 0x00000003
# A per-user service: the template (0x40) and each logon session's instance of
# it (0x40 | 0x80, named <template>_<LUID>). Instances come and go with every
# logon, under a new name each time -- an RDS host with 200 sessions has
# thousands -- and a template is never running, whatever its start type. Not
# reported: neither is a service an operator monitors.
SERVICE_USER_SERVICE = 0x00000040
SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 3
SERVICE_CONFIG_TRIGGER_INFO = 8

# winerror.h
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_SERVICE_DOES_NOT_EXIST = 1060

STATES = {
    1: "stopped",
    2: "start_pending",
    3: "stop_pending",
    4: "running",
    5: "continue_pending",
    6: "pause_pending",
    7: "paused",
}

# boot and system are driver start types; listed so a value the SCM can send
# never reads as unknown.
START_TYPES = {
    0: "boot",
    1: "system",
    2: "automatic",
    3: "manual",
    4: "disabled",
}

# A Windows Server lists 200-400 services once per-user ones are left out. Over
# this the whole tick reports None rather than a truncated list, which would
# read as services removed (the openvpn _MAX_INSTANCES posture).
MAX_SERVICES = 2000

# The whole read runs in a daemon worker abandoned after this long (the
# io_topology posture): the SCM answers from memory, but every call is an RPC
# to services.exe, and the collection loop must not wait on a wedged one.
SCM_READ_TIMEOUT = 10

# QueryServiceConfig2W's buffer is at most 8 KB (its documented maximum), so the
# first call fits; a larger `needed` is still honoured once.
_TRIGGER_BUFFER_BYTES = 8192

# The worker of a read (or a probe's open) that outlived SCM_READ_TIMEOUT, while
# it is still alive: no second read or probe starts until it returns.
_stalled_worker = None

# QueryServiceConfig2W from advapi32, with its argument types set once.
_query_config2 = None


class TooManyServices(Exception):
    pass


@debug("windows_services")
def windows_services():
    """{"services": [...]} for every Win32 service the agent can see, or None.

    See the module docstring for the payload and when it is None. A failed
    read raises, on the caller's thread, where the dispatcher logs it, records
    it in the collector's telemetry and reports None.
    """
    global _stalled_worker
    if not is_windows():
        return None
    if _still_blocked():
        log("windows_services: previous read still blocked; reporting None", "debug")
        return None

    try:
        return call_bounded(_read_services, SCM_READ_TIMEOUT, name="windows-services")
    except WorkerTimeout as stalled:
        _stalled_worker = stalled.worker
        log(
            f"windows_services: the Service Control Manager did not answer "
            f"within {SCM_READ_TIMEOUT}s; reporting None until it does",
            "error",
        )
        return None


def probe_access():
    """(available, reason) for the capability probe.

    The same pywin32 import and SCM open the collector makes, so the two
    cannot drift; the per-service reads are the collector's own business. The
    probe runs on the collection loop too (at start-up, on every full re-probe
    and on SIGHUP), so its open is bounded like the collector's read and shares
    its single flight: while either is blocked, neither starts again.
    """
    global _stalled_worker
    try:
        import win32service  # type: ignore[import-not-found]
    except ImportError as e:
        return False, f"pywin32 not installed: {e}"
    if _still_blocked():
        return False, "a Service Control Manager read is still blocked"

    def open_and_close():
        win32service.CloseServiceHandle(_open_scm(win32service))

    try:
        call_bounded(open_and_close, SCM_READ_TIMEOUT, name="windows-services-probe")
    except WorkerTimeout as stalled:
        _stalled_worker = stalled.worker
        return (
            False,
            f"Service Control Manager did not answer within {SCM_READ_TIMEOUT}s",
        )
    except Exception as e:
        return False, f"Service Control Manager unavailable: {type(e).__name__}: {e}"
    return True, None


def _still_blocked():
    """True while a read or probe abandoned at SCM_READ_TIMEOUT has not returned."""
    global _stalled_worker
    if _stalled_worker is not None and not _stalled_worker.is_alive():
        _stalled_worker = None
    return _stalled_worker is not None


def _open_scm(win32service):
    return win32service.OpenSCManager(
        None, None, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE
    )


def _read_services():
    import win32service  # type: ignore[import-not-found]

    scm = _open_scm(win32service)
    try:
        rows = [
            row
            for row in win32service.EnumServicesStatusEx(
                scm, SERVICE_WIN32, SERVICE_STATE_ALL
            )
            if not row["ServiceType"] & SERVICE_USER_SERVICE
        ]
        if len(rows) > MAX_SERVICES:
            raise TooManyServices(
                f"{len(rows)} services listed, over the {MAX_SERVICES} the agent "
                "reports"
            )
        services = []
        for row in rows:
            entry = _service_entry(win32service, scm, row)
            if entry is not None:
                services.append(entry)
    finally:
        win32service.CloseServiceHandle(scm)
    services.sort(key=lambda s: (s["name"].casefold(), s["name"]))
    return {"services": services}


def _service_entry(win32service, scm, row):
    """One service's row, or None when it was deleted since the listing."""
    name = row["ServiceName"]
    config = _service_config(win32service, scm, name)
    if config is None:
        return None
    start_type, delayed, trigger = config
    return {
        "name": scrub_str(name),
        "display_name": scrub_str(row["DisplayName"]),
        "state": STATES.get(row["CurrentState"]),
        "start_type": start_type,
        "delayed_auto_start": delayed,
        "trigger_start": trigger,
        # 0 when the service has no process (stopped, or still starting).
        "pid": row["ProcessId"] or None,
        # Win32ExitCode; 1066 (ERROR_SERVICE_SPECIFIC_ERROR) means the service
        # set its own code, service_exit_code. Both shipped raw.
        "exit_code": row["Win32ExitCode"],
        "service_exit_code": row["ServiceSpecificExitCode"],
    }


def _service_config(win32service, scm, name):
    """(start_type, delayed_auto_start, trigger_start), each None when it could
    not be read; None when the service no longer exists."""
    try:
        handle = win32service.OpenService(scm, name, SERVICE_QUERY_CONFIG)
    except Exception as e:
        if getattr(e, "winerror", None) == ERROR_SERVICE_DOES_NOT_EXIST:
            return None
        # A service whose security descriptor grants the agent's account its
        # status but not its configuration: listed, configuration unknown.
        # log_safe: a name or OS message is redacted and kept ASCII. A
        # character outside the code page of a Windows service's stdout made
        # print() raise and sink the whole read until log() stopped raising
        # on encoding (#273); the escape stays as defence in depth.
        log(f"windows_services: cannot open {log_safe(name)}: {log_safe(e)}", "debug")
        return None, None, None
    try:
        start_type = _read(
            name,
            "start type",
            lambda: START_TYPES.get(win32service.QueryServiceConfig(handle)[1]),
        )
        delayed = _read(
            name,
            "delayed start",
            lambda: bool(
                win32service.QueryServiceConfig2(
                    handle, SERVICE_CONFIG_DELAYED_AUTO_START_INFO
                )
            ),
        )
        trigger = _read(name, "triggers", lambda: _trigger_count(int(handle)) > 0)
    finally:
        win32service.CloseServiceHandle(handle)
    return start_type, delayed, trigger


def _read(name, what, fn):
    try:
        return fn()
    except Exception as e:
        log(
            f"windows_services: cannot read the {what} of {log_safe(name)}: "
            f"{log_safe(e)}",
            "debug",
        )
        return None


def _query_config2_w():
    global _query_config2
    if _query_config2 is None:
        import ctypes
        from ctypes import wintypes

        fn = ctypes.WinDLL(  # type: ignore[attr-defined]
            "advapi32", use_last_error=True
        ).QueryServiceConfig2W
        fn.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )
        fn.restype = wintypes.BOOL
        _query_config2 = fn
    return _query_config2


def _trigger_count(handle):
    """SERVICE_TRIGGER_INFO.cTriggers: how many start/stop triggers the service
    has. A service with any is shown as "(Trigger Start)" by services.msc, and
    starts and stops on its own (a device, a network event, a policy change)."""
    import ctypes
    from ctypes import wintypes

    query = _query_config2_w()
    size = _TRIGGER_BUFFER_BYTES
    for _ in range(2):
        buffer = ctypes.create_string_buffer(size)
        needed = wintypes.DWORD(0)
        if query(
            handle, SERVICE_CONFIG_TRIGGER_INFO, buffer, size, ctypes.byref(needed)
        ):
            # cTriggers is the struct's first member.
            return wintypes.DWORD.from_buffer(buffer).value
        error = ctypes.get_last_error()  # type: ignore[attr-defined]
        if error != ERROR_INSUFFICIENT_BUFFER or needed.value <= size:
            break
        size = needed.value
    raise OSError(
        f"QueryServiceConfig2W(SERVICE_CONFIG_TRIGGER_INFO) failed: error {error}"
    )
