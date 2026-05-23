"""Tests for the persistent per-agent machine id."""

import os
import sys
import uuid
from unittest.mock import patch

import pytest

from fivenines_agent.machine_id import (
    MACHINE_ID_FILENAME,
    _persist_id,
    _read_persisted_id,
    _valid_uuid,
    get_machine_id,
)

# --- _valid_uuid -----------------------------------------------------------


def test_valid_uuid_accepts_uuid4():
    assert _valid_uuid(str(uuid.uuid4())) is True


def test_valid_uuid_rejects_garbage():
    assert _valid_uuid("not-a-uuid") is False


def test_valid_uuid_rejects_empty_string():
    assert _valid_uuid("") is False


def test_valid_uuid_rejects_non_string():
    assert _valid_uuid(None) is False


# --- _read_persisted_id ----------------------------------------------------


def test_read_persisted_id_returns_valid_uuid(tmp_path):
    path = tmp_path / MACHINE_ID_FILENAME
    value = str(uuid.uuid4())
    path.write_text(value)
    assert _read_persisted_id(str(path)) == value


def test_read_persisted_id_returns_none_when_missing(tmp_path):
    path = tmp_path / MACHINE_ID_FILENAME
    assert _read_persisted_id(str(path)) is None


def test_read_persisted_id_returns_none_when_corrupt(tmp_path):
    path = tmp_path / MACHINE_ID_FILENAME
    path.write_text("not-a-valid-uuid")
    assert _read_persisted_id(str(path)) is None


def test_read_persisted_id_returns_none_on_os_error(tmp_path):
    # A directory where a file is expected raises IsADirectoryError, an
    # OSError that is not FileNotFoundError -- exercises the OSError branch.
    path = tmp_path / MACHINE_ID_FILENAME
    path.mkdir()
    assert _read_persisted_id(str(path)) is None


# --- _persist_id -----------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "Windows os.chmod does not honor POSIX granular modes; "
        "the agent's actual file protection on Windows comes from the "
        "MSI's util:PermissionEx on the config dir (Admin + SYSTEM + "
        "service account only), not from chmod."
    ),
)
def test_persist_id_writes_file_owner_only(tmp_path):
    path = tmp_path / MACHINE_ID_FILENAME
    value = str(uuid.uuid4())
    assert _persist_id(str(path), value) is True
    assert path.read_text() == value
    assert (path.stat().st_mode & 0o777) == 0o600


def test_persist_id_returns_false_on_os_error(tmp_path):
    # Parent directory does not exist -> FileNotFoundError (an OSError).
    path = tmp_path / "missing_dir" / MACHINE_ID_FILENAME
    assert _persist_id(str(path), str(uuid.uuid4())) is False


# --- get_machine_id --------------------------------------------------------


def test_get_machine_id_generates_and_persists(tmp_path):
    with patch("fivenines_agent.machine_id.config_dir", return_value=str(tmp_path)):
        result = get_machine_id()
    assert _valid_uuid(result)
    assert (tmp_path / MACHINE_ID_FILENAME).read_text() == result


def test_get_machine_id_reuses_existing_file(tmp_path):
    existing = str(uuid.uuid4())
    (tmp_path / MACHINE_ID_FILENAME).write_text(existing)
    with patch("fivenines_agent.machine_id.config_dir", return_value=str(tmp_path)):
        assert get_machine_id() == existing


def test_get_machine_id_is_stable_across_calls(tmp_path):
    with patch("fivenines_agent.machine_id.config_dir", return_value=str(tmp_path)):
        first = get_machine_id()
        second = get_machine_id()
    assert first == second


def test_get_machine_id_returns_none_when_not_persistable(tmp_path):
    # config_dir points at a directory that does not exist, so neither the
    # read nor the write can succeed.
    unwritable = os.path.join(str(tmp_path), "missing_dir")
    with patch("fivenines_agent.machine_id.config_dir", return_value=unwritable):
        assert get_machine_id() is None


def test_get_machine_id_never_raises():
    with patch(
        "fivenines_agent.machine_id.config_dir",
        side_effect=RuntimeError("unexpected"),
    ):
        assert get_machine_id() is None
