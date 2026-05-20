"""Tests for files.py - file-handle metrics on Linux + Windows handle count."""

import builtins
from unittest.mock import MagicMock, mock_open, patch

from fivenines_agent.files import (
    file_handles_limit,
    file_handles_stats,
    file_handles_used,
    handle_count,
)


# --- Linux file-nr path ---


def test_file_handles_stats_linux_parses_file_nr():
    with patch("fivenines_agent.files.os_family", return_value="linux"), \
         patch("builtins.open", mock_open(read_data="1024\t0\t65536\n")):
        assert file_handles_stats() == [1024, 0, 65536]


def test_file_handles_stats_non_linux_returns_zeros():
    with patch("fivenines_agent.files.os_family", return_value="darwin"):
        assert file_handles_stats() == [0, 0, 0]


def test_file_handles_stats_missing_file_returns_zeros():
    def fake_open(*args, **kwargs):
        raise FileNotFoundError
    with patch("fivenines_agent.files.os_family", return_value="linux"), \
         patch.object(builtins, "open", fake_open):
        assert file_handles_stats() == [0, 0, 0]


def test_file_handles_used_returns_first_field():
    with patch("fivenines_agent.files.file_handles_stats", return_value=[42, 0, 65536]):
        assert file_handles_used() == 42


def test_file_handles_limit_returns_third_field():
    with patch("fivenines_agent.files.file_handles_stats", return_value=[42, 0, 65536]):
        assert file_handles_limit() == 65536


# --- Windows handle_count via PDH ---


def test_handle_count_returns_int_on_success():
    fake = MagicMock()
    fake.OpenQuery.return_value = "QUERY"
    fake.AddCounter.return_value = "COUNTER"
    fake.PDH_FMT_LONG = 0x100
    fake.GetFormattedCounterValue.return_value = (0, 12345)
    with patch.dict("sys.modules", {"win32pdh": fake}):
        assert handle_count() == 12345
    fake.OpenQuery.assert_called_once()
    fake.AddCounter.assert_called_once_with("QUERY", r"\Process(_Total)\Handle Count")
    fake.CollectQueryData.assert_called_once_with("QUERY")
    fake.CloseQuery.assert_called_once_with("QUERY")


def test_handle_count_closes_query_even_when_query_fails():
    """If GetFormattedCounterValue raises, CloseQuery still runs."""
    fake = MagicMock()
    fake.OpenQuery.return_value = "QUERY"
    fake.AddCounter.return_value = "COUNTER"
    fake.PDH_FMT_LONG = 0x100
    fake.GetFormattedCounterValue.side_effect = OSError("PDH broken")
    with patch.dict("sys.modules", {"win32pdh": fake}):
        assert handle_count() is None
    fake.CloseQuery.assert_called_once_with("QUERY")


def test_handle_count_returns_none_when_pywin32_missing():
    """No pywin32 (non-Windows or missing dep) -> None, no crash."""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "win32pdh":
            raise ImportError("not installed")
        return real_import(name, *args, **kwargs)

    with patch.object(builtins, "__import__", fake_import):
        assert handle_count() is None


def test_handle_count_returns_none_on_openquery_failure():
    """OpenQuery raising is caught and returns None (PDH service not running)."""
    fake = MagicMock()
    fake.OpenQuery.side_effect = OSError("PDH service down")
    with patch.dict("sys.modules", {"win32pdh": fake}):
        assert handle_count() is None
