"""Tests for the console entry point (fivenines_agent.__main__) and the CLI.

pyproject.toml maps the `fivenines_agent` script to __main__.start, and
`python -m fivenines_agent` runs __main__.py as a script (so does the
PyInstaller entry script, py2exe_entrypoint.py). All must parse the command
line BEFORE importing the agent module, so `--version` exits without ever
loading the collector graph, touching the config dir, the API or the
collection loop. The Agent is always mocked here: no test may start the real
agent.
"""

import importlib.util
import runpy
import subprocess
import sys
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

import fivenines_agent.__main__ as main_module
from fivenines_agent import cli


def _argv(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["fivenines_agent", *args])


REPO_ROOT = Path(__file__).resolve().parent.parent


# --- cli.parse_args / cli.get_args ----------------------------------------


def test_get_args_is_none_before_parse_args():
    """The module default, read from a fresh copy of cli.py: the conftest
    fixture sets cli._args to None before every test, so the shared module
    would only echo that."""
    spec = importlib.util.spec_from_file_location("_fresh_cli", cli.__file__)
    fresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fresh)
    assert fresh.get_args() is None


def test_parse_args_without_flags(monkeypatch):
    _argv(monkeypatch)
    args = cli.parse_args()
    assert args == Namespace(dry_run=False, check_imports=False)
    assert cli.get_args() is args


def test_parse_args_dry_run(monkeypatch):
    _argv(monkeypatch, "--dry-run")
    args = cli.parse_args()
    assert args.dry_run is True
    assert cli.get_args() is args


def test_parse_args_check_imports(monkeypatch):
    _argv(monkeypatch, "--check-imports")
    args = cli.parse_args()
    assert args.check_imports is True
    assert args.dry_run is False


def test_parse_args_version_prints_and_exits_zero(monkeypatch, capsys):
    _argv(monkeypatch, "--version")
    with pytest.raises(SystemExit) as exc:
        cli.parse_args()
    assert exc.value.code == 0
    assert capsys.readouterr().out == f"fivenines-agent {cli.VERSION}\n"
    # argparse exits before the assignment: nothing is stored.
    assert cli.get_args() is None


def test_parse_args_unknown_flag_exits_with_usage_error(monkeypatch, capsys):
    _argv(monkeypatch, "--no-such-flag")
    with pytest.raises(SystemExit) as exc:
        cli.parse_args()
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "unrecognized arguments: --no-such-flag" in err
    assert cli.get_args() is None


# --- __main__.start ---------------------------------------------------------


def test_start_parses_args_before_building_and_running_the_agent(monkeypatch):
    calls = MagicMock()
    calls.parse_args.return_value = Namespace(dry_run=False, check_imports=False)
    monkeypatch.setattr(main_module, "parse_args", calls.parse_args)
    monkeypatch.setattr("fivenines_agent.agent.Agent", calls.Agent)

    main_module.start()

    assert calls.mock_calls == [call.parse_args(), call.Agent(), call.Agent().run()]


def test_start_version_exits_before_the_agent_is_built(monkeypatch, capsys):
    """The real parser: --version must end the process before Agent()."""
    _argv(monkeypatch, "--version")
    agent_cls = MagicMock()
    monkeypatch.setattr("fivenines_agent.agent.Agent", agent_cls)

    with pytest.raises(SystemExit) as exc:
        main_module.start()

    assert exc.value.code == 0
    assert capsys.readouterr().out == f"fivenines-agent {cli.VERSION}\n"
    agent_cls.assert_not_called()


def test_start_version_never_imports_the_agent(monkeypatch, capsys):
    """A None entry in sys.modules makes any import of the module raise
    ImportError, so --version must exit 0 without ever reaching it."""
    _argv(monkeypatch, "--version")
    monkeypatch.setitem(sys.modules, "fivenines_agent.agent", None)

    with pytest.raises(SystemExit) as exc:
        main_module.start()

    assert exc.value.code == 0
    assert capsys.readouterr().out == f"fivenines-agent {cli.VERSION}\n"


@pytest.mark.parametrize(
    "script",
    [
        # The console script / python -m path.
        "from fivenines_agent.__main__ import start\nstart()\n",
        # The frozen binary's entry script, run exactly as PyInstaller runs it.
        "import runpy\nrunpy.run_path(%r, run_name='__main__')\n"
        % str(REPO_ROOT / "py2exe_entrypoint.py"),
    ],
    ids=["start", "py2exe_entrypoint"],
)
def test_version_in_a_fresh_interpreter_loads_no_collector_module(script):
    """End to end, in a clean process (this one has long imported everything):
    --version must load neither the agent nor any of its heavy dependencies.
    This is what keeps `fivenines_agent --version` fast."""
    heavy = [
        "fivenines_agent.agent",
        "fivenines_agent.collectors",
        "psutil",
        "requests",
        "docker",
        "pg8000",
    ]
    probe = (
        "import sys\n"
        "sys.argv = ['fivenines_agent', '--version']\n"
        "try:\n"
        + "".join(f"    {line}\n" for line in script.splitlines())
        + "except SystemExit as exc:\n"
        "    assert exc.code == 0, exc.code\n"
        f"print(sorted(m for m in {heavy!r} if m in sys.modules))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [f"fivenines-agent {cli.VERSION}", "[]"]


def test_start_check_imports_imports_the_agent_then_exits_without_building_it(
    monkeypatch, capsys
):
    """The real parser: --check-imports goes through the agent import (the
    frozen binary's smoke check; the test below shows a failing import fails
    it) and returns before Agent() reads any config."""
    _argv(monkeypatch, "--check-imports")
    agent_cls = MagicMock()
    monkeypatch.setattr("fivenines_agent.agent.Agent", agent_cls)

    main_module.start()

    assert capsys.readouterr().out == f"fivenines-agent {cli.VERSION}: agent imported\n"
    agent_cls.assert_not_called()


def test_start_check_imports_fails_when_the_agent_cannot_be_imported(monkeypatch):
    """What the build smoke check relies on: a module that cannot be imported
    makes --check-imports raise (a non-zero exit in the frozen binary)."""
    _argv(monkeypatch, "--check-imports")
    monkeypatch.setitem(sys.modules, "fivenines_agent.agent", None)

    with pytest.raises(ImportError):
        main_module.start()


def test_start_dry_run_flag_is_visible_to_the_agent(monkeypatch):
    """Agent() reads --dry-run through env.dry_run() -> cli.get_args(), so the
    flag must already be parsed when the Agent is constructed."""
    from fivenines_agent.env import dry_run

    _argv(monkeypatch, "--dry-run")
    seen = []
    agent_cls = MagicMock(side_effect=lambda: seen.append(dry_run()) or MagicMock())
    monkeypatch.setattr("fivenines_agent.agent.Agent", agent_cls)

    main_module.start()

    assert seen == [True]


# --- python -m fivenines_agent ----------------------------------------------


def _run_main_module(monkeypatch, run_name):
    # runpy warns when the module it is about to execute is already imported
    # (this file imports it above); monkeypatch puts the entry back afterwards.
    monkeypatch.delitem(sys.modules, "fivenines_agent.__main__", raising=False)
    calls = MagicMock()
    calls.parse_args.return_value = Namespace(dry_run=False, check_imports=False)
    with patch("fivenines_agent.cli.parse_args", calls.parse_args), patch(
        "fivenines_agent.agent.Agent", calls.Agent
    ):
        runpy.run_module("fivenines_agent", run_name=run_name)
    return calls


def test_python_dash_m_runs_start(monkeypatch):
    calls = _run_main_module(monkeypatch, "__main__")
    assert calls.mock_calls == [call.parse_args(), call.Agent(), call.Agent().run()]


def test_importing_the_entry_module_does_not_start_the_agent(monkeypatch):
    calls = _run_main_module(monkeypatch, "fivenines_agent.__main__")
    assert calls.mock_calls == []
