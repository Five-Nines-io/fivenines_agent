import time
from contextlib import ContextDecorator
from functools import wraps
from fivenines_agent.env import dry_run

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
            print(f"{self.name} ({(end - self.start)*1000:.0f} ms): {res!r}")
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
                print(f"{self.name} - {args[1:]} ({(end - start)*1000:.0f} ms): {result!r}")
            else:
                print(f"{self.name} ({(end - start)*1000:.0f} ms): {result!r}")
            return result

        return wrapper
