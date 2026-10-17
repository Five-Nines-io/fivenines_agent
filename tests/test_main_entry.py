"""Tests for the console entry point (fivenines_agent.__main__) and the CLI.

pyproject.toml maps the `fivenines_agent` script to __main__.start, and
`python -m fivenines_agent` runs __main__.py as a script. Both must parse the
command line BEFORE building the Agent, so `--version` exits without ever
touching the config dir, the API or the collection loop. The Agent is always
mocked here: no test may start the real agent.
"""

import runpy
import sys
from argparse import Namespace
from unittest.mock import MagicMock, call, patch

import pytest

import fivenines_agent.__main__ as main_module
from fivenines_agent import cli


def _argv(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["fivenines_agent", *args])


# --- cli.parse_args / cli.get_args ----------------------------------------


def test_get_args_is_none_before_parse_args():
    assert cli.get_args() is None


def test_parse_args_without_flags(monkeypatch):
    _argv(monkeypatch)
    args = cli.parse_args()
    assert args == Namespace(dry_run=False)
    assert cli.get_args() is args


def test_parse_args_dry_run(monkeypatch):
    _argv(monkeypatch, "--dry-run")
    args = cli.parse_args()
    assert args.dry_run is True
    assert cli.get_args() is args


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
    monkeypatch.setattr(main_module, "parse_args", calls.parse_args)
    monkeypatch.setattr(main_module, "Agent", calls.Agent)

    main_module.start()

    assert calls.mock_calls == [call.parse_args(), call.Agent(), call.Agent().run()]


def test_start_version_exits_before_the_agent_is_built(monkeypatch, capsys):
    """The real parser: --version must end the process before Agent()."""
    _argv(monkeypatch, "--version")
    agent_cls = MagicMock()
    monkeypatch.setattr(main_module, "Agent", agent_cls)

    with pytest.raises(SystemExit) as exc:
        main_module.start()

    assert exc.value.code == 0
    assert capsys.readouterr().out == f"fivenines-agent {cli.VERSION}\n"
    agent_cls.assert_not_called()


def test_start_dry_run_flag_is_visible_to_the_agent(monkeypatch):
    """Agent() reads --dry-run through env.dry_run() -> cli.get_args(), so the
    flag must already be parsed when the Agent is constructed."""
    from fivenines_agent.env import dry_run

    _argv(monkeypatch, "--dry-run")
    monkeypatch.delenv("DRY_RUN", raising=False)
    seen = []
    agent_cls = MagicMock(side_effect=lambda: seen.append(dry_run()) or MagicMock())
    monkeypatch.setattr(main_module, "Agent", agent_cls)

    main_module.start()

    assert seen == [True]


# --- python -m fivenines_agent ----------------------------------------------


def _run_main_module(monkeypatch, run_name):
    # runpy warns when the module it is about to execute is already imported
    # (this file imports it above); monkeypatch puts the entry back afterwards.
    monkeypatch.delitem(sys.modules, "fivenines_agent.__main__", raising=False)
    calls = MagicMock()
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
