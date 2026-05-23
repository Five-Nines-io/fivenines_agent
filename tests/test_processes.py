"""Tests for the processes collector.

The collector wraps psutil.process_iter() but explicitly filters out
PID 0 - on Windows that's the 'System Idle Process' pseudo-entry which
otherwise dominates 'Top CPU' rankings with ~(cpu_count * 100)% values.
"""

from unittest.mock import MagicMock, patch

from fivenines_agent.processes import processes


def _fake_proc(pid, name, cpu_percent=1.0):
    proc = MagicMock()
    proc.pid = pid
    proc.as_dict.return_value = {
        "pid": pid,
        "ppid": 0,
        "name": name,
        "username": "test",
        "memory_percent": 0.0,
        "cpu_percent": cpu_percent,
        "cpu_times": None,
        "num_threads": 1,
        "status": "running",
    }
    return proc


def test_filters_pid_zero():
    """PID 0 ('System Idle Process' on Windows) must not appear in the payload."""
    fake_procs = [
        _fake_proc(0, "System Idle Process", cpu_percent=400.0),
        _fake_proc(4, "System", cpu_percent=1.0),
        _fake_proc(1234, "fivenines-agent.exe", cpu_percent=10.0),
    ]
    with patch("fivenines_agent.processes.psutil.process_iter",
               return_value=iter(fake_procs)):
        result = processes()
    pids = [p["pid"] for p in result]
    assert 0 not in pids, "PID 0 leaked into the processes payload"
    # Other kernel/system processes (PID 4 = 'System') are kept - they're
    # real processes that can legitimately consume CPU during I/O.
    assert 4 in pids
    assert 1234 in pids


def test_skips_nosuchprocess():
    """psutil.NoSuchProcess raised mid-iteration is swallowed, not propagated."""
    import psutil
    good = _fake_proc(100, "ok.exe")
    raising = MagicMock()
    raising.pid = 200
    raising.as_dict.side_effect = psutil.NoSuchProcess(pid=200)
    with patch("fivenines_agent.processes.psutil.process_iter",
               return_value=iter([good, raising])):
        result = processes()
    pids = [p["pid"] for p in result]
    assert pids == [100]
