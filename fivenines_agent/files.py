"""File-handle metrics.

Linux exposes used/unused/max file descriptor counts via
``/proc/sys/fs/file-nr``. Windows has no equivalent system-wide
file-descriptor counter; ``handle_count`` reports total kernel handles via the
PDH counter ``\\Process(_Total)\\Handle Count`` (a related but semantically
different metric per D10, sent under its own key so the backend does not
conflate the two).
"""

from fivenines_agent.debug import debug
from fivenines_agent.env import os_family


@debug('file_handles_used')
def file_handles_used():
    return file_handles_stats()[0]


@debug('file_handles_limit')
def file_handles_limit():
    return file_handles_stats()[2]


def file_handles_stats():
    """Read /proc/sys/fs/file-nr on Linux; return zeros elsewhere."""
    if os_family() != 'linux':
        return [0, 0, 0]
    try:
        with open('/proc/sys/fs/file-nr', 'r') as f:
            return list(map(int, f.read().strip().split('\t')))
    except FileNotFoundError:
        return [0, 0, 0]


@debug('handle_count')
def handle_count():
    """Windows total kernel handle count via PDH.

    Returns the integer count on Windows when the PDH query succeeds, or None
    when pywin32 is unavailable or the query fails. Linux callers should not
    reach here - agent._collect_file_handles routes on is_windows().
    """
    try:
        import win32pdh  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        query = win32pdh.OpenQuery()
        try:
            counter = win32pdh.AddCounter(query, r"\Process(_Total)\Handle Count")
            win32pdh.CollectQueryData(query)
            _, value = win32pdh.GetFormattedCounterValue(counter, win32pdh.PDH_FMT_LONG)
            return int(value)
        finally:
            win32pdh.CloseQuery(query)
    except Exception as e:
        from fivenines_agent.debug import log
        log(f"handle_count: PDH query failed: {e}", "debug")
        return None
