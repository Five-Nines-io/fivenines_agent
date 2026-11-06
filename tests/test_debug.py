"""Tests for the @debug timing decorator / context manager.

Outside dry-run the decorator is a pass-through and logs nothing; under
dry-run (DRY_RUN=true or --dry-run) it times each call and prints the result
at debug level, which dry-run always enables. The clock is replaced with a
scripted one so the printed millisecond figure is exact.
"""

import io
import re
import sys
from types import SimpleNamespace

import pytest

import fivenines_agent.debug as debug_module
from fivenines_agent import cli
from fivenines_agent.debug import debug


@pytest.fixture
def dry_run_mode(monkeypatch):
    monkeypatch.setenv("DRY_RUN", "true")


@pytest.fixture
def clock(monkeypatch):
    """Scripted monotonic clock for the debug module only (the time module
    itself is left alone, so nothing else in the process sees it)."""

    def install(*readings):
        ticks = iter(readings)
        monkeypatch.setattr(
            debug_module, "time", SimpleNamespace(monotonic=lambda: next(ticks))
        )

    return install


LINE = re.compile(r"^\[DEBUG\]\[thread#\d+\] (?P<message>.*)$")


def _messages(capsys):
    lines = capsys.readouterr().out.splitlines()
    messages = []
    for line in lines:
        match = LINE.match(line)
        assert match, f"unexpected output line: {line!r}"
        messages.append(match.group("message"))
    return messages


# --- decorator ---------------------------------------------------------------


def test_decorator_outside_dry_run_is_a_silent_pass_through(capsys):
    @debug("probe")
    def probe(a, b=0):
        return a + b

    assert probe(2, b=3) == 5
    assert capsys.readouterr().out == ""


def test_decorator_preserves_the_wrapped_function_metadata():
    @debug("probe")
    def probe():
        """Docstring."""

    assert probe.__name__ == "probe"
    assert probe.__doc__ == "Docstring."


def test_decorator_dry_run_logs_name_duration_and_result(dry_run_mode, clock, capsys):
    clock(10.0, 10.25)

    @debug("memory")
    def collect():
        return {"total": 1}

    assert collect() == {"total": 1}
    assert _messages(capsys) == ["memory (250 ms): {'total': 1}"]


def test_decorator_dry_run_single_argument_is_not_logged(dry_run_mode, clock, capsys):
    """args[0] is `self` for a method, so a lone argument is never printed."""
    clock(0.0, 0.004)

    @debug("one_arg")
    def collect(value):
        return None

    assert collect("first") is None
    assert _messages(capsys) == ["one_arg (4 ms): None"]


def test_decorator_dry_run_logs_arguments_after_the_first(dry_run_mode, clock, capsys):
    clock(1.0, 1.5)

    class Collector:
        @debug("collector.read")
        def read(self, host, port):
            return [host, port]

    assert Collector().read("db", 5432) == ["db", 5432]
    assert _messages(capsys) == ["collector.read - ('db', 5432) (500 ms): ['db', 5432]"]


def test_decorator_dry_run_via_parsed_args(clock, monkeypatch, capsys):
    """--dry-run on the command line enables it as well as DRY_RUN=true."""
    monkeypatch.setattr(cli, "_args", SimpleNamespace(dry_run=True))
    clock(0.0, 0.0)

    @debug("cli_flag")
    def collect():
        return 7

    assert collect() == 7
    assert _messages(capsys) == ["cli_flag (0 ms): 7"]


def test_decorator_dry_run_exception_propagates_without_a_log_line(
    dry_run_mode, clock, capsys
):
    clock(0.0, 1.0)

    @debug("boom")
    def collect():
        raise ValueError("bad read")

    with pytest.raises(ValueError, match="bad read"):
        collect()
    assert capsys.readouterr().out == ""


# --- context manager -----------------------------------------------------------


def test_context_manager_outside_dry_run_logs_nothing(capsys):
    with debug("block") as d:
        d.result = "ignored"
    assert capsys.readouterr().out == ""


def test_context_manager_dry_run_logs_the_result_attribute(dry_run_mode, clock, capsys):
    clock(5.0, 5.012)
    with debug("json_serialize") as d:
        d.result = "42 bytes"
    assert _messages(capsys) == ["json_serialize (12 ms): '42 bytes'"]


def test_context_manager_dry_run_without_result_logs_none(dry_run_mode, clock, capsys):
    clock(0.0, 0.1)
    with debug("no_result"):
        pass
    assert _messages(capsys) == ["no_result (100 ms): None"]


def test_context_manager_dry_run_does_not_swallow_exceptions(
    dry_run_mode, clock, capsys
):
    clock(0.0, 0.002)
    with pytest.raises(RuntimeError, match="gzip failed"):
        with debug("gzip_compress"):
            raise RuntimeError("gzip failed")
    # The timing line is still written on the way out.
    assert _messages(capsys) == ["gzip_compress (2 ms): None"]


# --- log() on a stdout that cannot encode the line (#273) ---


def _strict_cp1252_stdout(monkeypatch):
    """Make sys.stdout what a Windows service's is when start() did not run:
    the ANSI code page with errors="strict" (WinSW redirects it to the log
    file). Return a reader of the bytes written. Called from the test body:
    pytest re-installs its own capture stream after fixture setup."""
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    stream = io.TextIOWrapper(
        io.BytesIO(), encoding="cp1252", errors="strict", newline="\n"
    )
    monkeypatch.setattr(sys, "stdout", stream)

    def written():
        stream.flush()
        return stream.buffer.getvalue()

    return written


# Value: protects=a log line quoting a localized OS error never raises, so the
# except block logging it (the synchronizer's retry loop, Agent.run's last
# handler) completes and its thread lives on; fails_when=log() prints the line
# as is to a strict stdout and lets UnicodeEncodeError out, or swallows the
# line instead of writing it escaped, or the escape skips the telemetry
# capture; why_new=no test fed log() a stream that cannot encode its line;
# seam=none; no_claim=what start() does to the real stdout (test_main_entry).
def test_log_escapes_a_line_its_strict_stdout_cannot_encode(monkeypatch):
    written = _strict_cp1252_stdout(monkeypatch)
    message = "Synchronizer Error: [WinError 10060] \u63a5\u7d9a caf\u00e9"
    debug_module.start_log_capture()
    try:
        debug_module.log(message, "error")
    finally:
        captured = debug_module.stop_log_capture()

    # The whole line is escaped to ASCII, the e-acute cp1252 has included.
    assert re.fullmatch(
        rb"\[ERROR\]\[thread#\d+\] Synchronizer Error: \[WinError 10060\] "
        rb"\\u63a5\\u7d9a caf\\xe9\n",
        written(),
    )
    # Telemetry keeps the message as logged.
    assert captured == [message]


def test_log_writes_a_line_its_stdout_can_encode_unchanged(monkeypatch):
    written = _strict_cp1252_stdout(monkeypatch)

    debug_module.log("caf\u00e9", "error")

    assert re.fullmatch(rb"\[ERROR\]\[thread#\d+\] caf\xe9\n", written())
