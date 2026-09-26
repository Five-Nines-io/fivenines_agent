import threading
import time
from contextlib import ContextDecorator
from functools import wraps
from fivenines_agent.env import dry_run, log_level

_thread_local = threading.local()

LOG_LEVELS = {
    'debug': 0,
    'info': 1,
    'warn': 2,
    'error': 3,
    'critical': 4,
}


class debug(ContextDecorator):
    def __init__(self, name: str):
        self.name = name

    def __enter__(self):
        if dry_run():
            self.start = time.monotonic()
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        if dry_run():
            end = time.monotonic()
            res = getattr(self, '_wrapped_result',
                          getattr(self, 'result', None))
            log(f"{self.name} ({(end - self.start)*1000:.0f} ms): {res!r}", 'debug')
        return False

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not dry_run():
                return func(*args, **kwargs)

            start = time.monotonic()
            result = func(*args, **kwargs)
            end = time.monotonic()
            if len(args) > 1:
                log(f"{self.name} - {args[1:]} ({(end - start)*1000:.0f} ms): {result!r}", 'debug')
            else:
                log(f"{self.name} ({(end - start)*1000:.0f} ms): {result!r}", 'debug')
            return result

        return wrapper


def start_log_capture():
    _thread_local.log_buffer = []


def stop_log_capture():
    buffer = getattr(_thread_local, 'log_buffer', None)
    _thread_local.log_buffer = None
    return buffer or []


def current_log_capture():
    """This thread's active capture buffer, or None (see adopt_log_capture)."""
    return getattr(_thread_local, 'log_buffer', None)


def adopt_log_capture(buffer):
    """Send this thread's error lines to another thread's capture buffer.

    Capture is thread-local, so a collector that does its work on a worker
    thread (bounded.call_bounded) would otherwise log its errors past the
    dispatcher's telemetry. list.append is atomic, and a worker that outlives
    the tick only appends to a list nobody reads any more.
    """
    _thread_local.log_buffer = buffer


def debug_enabled():
    """True when 'debug' messages would actually be emitted.

    log() only checks the level AFTER its argument is built, so callers with
    expensive-to-build messages (json.dumps of a full payload, str() of a large
    dict) must gate on this first or they pay the serialization cost on every
    call even when the message is discarded.
    """
    return LOG_LEVELS[log_level()] <= LOG_LEVELS['debug']


def log(message, level='info'):
    if LOG_LEVELS[log_level()] <= LOG_LEVELS[level]:
        print(f"[{level.upper()}][thread#{threading.get_native_id()}] {message}")
    # Buffer error messages when capture is active (thread-local).
    # Intentionally outside the log-level check: errors are always
    # captured for backend telemetry regardless of configured log level.
    buffer = getattr(_thread_local, 'log_buffer', None)
    if buffer is not None and level == 'error':
        buffer.append(message)
