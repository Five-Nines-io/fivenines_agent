"""Run a call that may block without ever waiting past a deadline.

The collection loop is single-threaded and bounded by the systemd watchdog
(WatchdogSec=90). Some calls cannot be interrupted once they block: a sudo
child whose root-owned process the agent cannot kill, a wedged libvirt socket,
a kernfs readdir stuck behind reclaim. For those, the only protection is not
waiting: run the call on a daemon worker, stop waiting at the deadline, and
leave the worker to finish in the background.

Used by subprocess_utils.run_privileged, the libvirt capability probe and the
io_topology collector. Each caller keeps its own policy for the abandoned
worker (single-flight on it, or not) and its own failure value.
"""

import threading

from fivenines_agent.debug import adopt_log_capture, current_log_capture


class WorkerTimeout(Exception):
    """The call outlived its deadline. `worker` is the thread still running it."""

    def __init__(self, worker, timeout):
        super().__init__(f"call still running after {timeout}s")
        self.worker = worker


def call_bounded(fn, timeout, name=None):
    """Return fn() if it finishes within `timeout` seconds.

    Whatever fn raises is re-raised on the caller's thread, where the
    dispatcher's telemetry and the caller's own handlers can see it, and the
    error lines fn logs land in the caller's log capture too. When the deadline
    passes, raises WorkerTimeout carrying the still-running worker so the
    caller can refuse to start another behind it. The worker is a daemon, so
    the interpreter never waits for it at exit -- though a thread stuck in an
    uninterruptible kernel wait (D state) still delays the process's final
    exit until that wait ends; no userspace code can change that.
    """
    outcome = {}
    capture = current_log_capture()

    def target():
        adopt_log_capture(capture)
        try:
            outcome["value"] = fn()
        except BaseException as e:  # re-raised on the caller's thread below
            outcome["error"] = e

    worker = threading.Thread(target=target, name=name, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise WorkerTimeout(worker, timeout)
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]
