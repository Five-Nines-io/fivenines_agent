"""Tests for the backend-controlled recheck additions to PermissionProbe:
selective gap re-probe (refresh_due / _reprobe_capabilities) and the
openReadOnly-based libvirt probe with hard timeout.
"""

import threading
from unittest.mock import MagicMock, patch

import pytest

import fivenines_agent.permissions as perm
from fivenines_agent.permissions import PermissionProbe


@pytest.fixture(autouse=True)
def _force_linux():
    with patch("fivenines_agent.permissions.is_windows", return_value=False):
        yield


def _probe_obj(caps, last_probe_time=0, last_gap_probe_time=0):
    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = dict(caps)
    probe._capability_reasons = {}
    probe._current_reason = None
    probe._last_probe_time = last_probe_time
    probe._last_gap_probe_time = last_gap_probe_time
    return probe


# --- _reprobe_capabilities (selective gap probe) ---


def test_reprobe_flips_to_available_and_logs():
    probe = _probe_obj({"qemu": False, "cpu": True})
    with patch.object(PermissionProbe, "_can_access_libvirt", return_value=True), patch(
        "fivenines_agent.permissions.log"
    ) as mock_log:
        flipped = probe._reprobe_capabilities({"qemu"})
    assert flipped is True
    assert probe.capabilities["qemu"] is True
    info = [c.args[0] for c in mock_log.call_args_list if c.args[1] == "info"]
    assert any("qemu" in m and "now AVAILABLE" in m for m in info)


def test_reprobe_flips_to_unavailable_with_hint():
    probe = _probe_obj({"qemu": True})
    with patch.object(
        PermissionProbe, "_can_access_libvirt", return_value=False
    ), patch("fivenines_agent.permissions.log") as mock_log:
        flipped = probe._reprobe_capabilities({"qemu"})
    assert flipped is True
    assert probe.capabilities["qemu"] is False
    info = [c.args[0] for c in mock_log.call_args_list if c.args[1] == "info"]
    flip = next(m for m in info if "qemu" in m and "now UNAVAILABLE" in m)
    assert "requires libvirt group" in flip


def test_reprobe_no_flip_returns_false():
    probe = _probe_obj({"qemu": True})
    with patch.object(PermissionProbe, "_can_access_libvirt", return_value=True):
        assert probe._reprobe_capabilities({"qemu"}) is False
    assert probe.capabilities["qemu"] is True


def test_reprobe_skips_unknown_capability():
    probe = _probe_obj({"qemu": False})
    assert probe._reprobe_capabilities({"not_a_capability"}) is False
    assert "not_a_capability" not in probe.capabilities


# --- refresh_due (cadence) ---


def test_refresh_due_full_probe_when_interval_elapsed():
    probe = _probe_obj({"qemu": False}, last_probe_time=0)

    def fake_full():
        probe.capabilities = {"qemu": True}

    with patch.object(probe, "_probe_all", side_effect=fake_full):
        changed = probe.refresh_due({"qemu"}, 0)
    assert changed is True
    assert probe.capabilities == {"qemu": True}


def test_refresh_due_full_probe_no_change_returns_false():
    probe = _probe_obj({"qemu": True}, last_probe_time=0)
    with patch.object(probe, "_probe_all", side_effect=lambda: None):
        assert probe.refresh_due((), 0) is False


def test_refresh_due_gap_probe_when_not_due_for_full():
    import time

    probe = _probe_obj(
        {"qemu": False}, last_probe_time=time.time(), last_gap_probe_time=0
    )
    with patch.object(PermissionProbe, "_can_access_libvirt", return_value=True):
        changed = probe.refresh_due({"qemu"}, 0)
    assert changed is True
    assert probe.capabilities["qemu"] is True


def test_refresh_due_empty_gap_is_noop():
    import time

    probe = _probe_obj(
        {"qemu": False}, last_probe_time=time.time(), last_gap_probe_time=0
    )
    assert probe.refresh_due((), 0) is False
    assert probe.capabilities["qemu"] is False


def test_refresh_due_gap_throttled_not_due():
    import time

    now = time.time()
    probe = _probe_obj({"qemu": False}, last_probe_time=now, last_gap_probe_time=now)
    # gap_interval huge -> the gap probe is not due yet
    assert probe.refresh_due({"qemu"}, 9999) is False
    assert probe.capabilities["qemu"] is False


def test_probe_all_resets_gap_probe_timer():
    # A full probe must reset the gap-probe clock so a force_refresh / startup /
    # SIGHUP full probe does not leave the next tick re-probing the same caps.
    probe = _probe_obj({}, last_probe_time=0, last_gap_probe_time=0)
    with patch.object(probe, "_build_linux_capabilities", return_value={"cpu": True}):
        probe._probe_all()
    assert probe._last_gap_probe_time == probe._last_probe_time
    assert probe._last_gap_probe_time > 0


def test_force_refresh_resets_gap_probe_timer():
    probe = _probe_obj({}, last_probe_time=0, last_gap_probe_time=0)
    with patch.object(probe, "_build_linux_capabilities", return_value={"cpu": True}):
        probe.force_refresh()
    assert probe._last_gap_probe_time == probe._last_probe_time > 0


# --- _can_access_libvirt (openReadOnly + hard timeout) ---


def test_libvirt_probe_module_not_importable():
    probe = _probe_obj({})
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "libvirt":
            raise ImportError("no libvirt")
        return real_import(name, *a, **k)

    with patch.object(builtins, "__import__", fake_import):
        assert probe._can_access_libvirt() is False
    assert probe._current_reason == "libvirt module not available"


def test_libvirt_probe_connects():
    probe = _probe_obj({})
    fake_libvirt = MagicMock()
    conn = MagicMock()
    fake_libvirt.openReadOnly.return_value = conn
    with patch.dict("sys.modules", {"libvirt": fake_libvirt}):
        assert probe._can_access_libvirt() is True
    fake_libvirt.openReadOnly.assert_called_once_with("qemu:///system")
    conn.close.assert_called_once()


def test_libvirt_probe_returns_none():
    probe = _probe_obj({})
    fake_libvirt = MagicMock()
    fake_libvirt.openReadOnly.return_value = None
    with patch.dict("sys.modules", {"libvirt": fake_libvirt}):
        assert probe._can_access_libvirt() is False
    assert probe._current_reason == "openReadOnly returned None"


def test_libvirt_probe_raises():
    probe = _probe_obj({})
    fake_libvirt = MagicMock()
    fake_libvirt.openReadOnly.side_effect = RuntimeError("boom")
    with patch.dict("sys.modules", {"libvirt": fake_libvirt}):
        assert probe._can_access_libvirt() is False
    assert probe._current_reason == "RuntimeError: boom"


def test_libvirt_probe_swallows_close_error():
    """A failing conn.close() must not break the probe: connection succeeded."""
    probe = _probe_obj({})
    fake_libvirt = MagicMock()
    conn = MagicMock()
    conn.close.side_effect = RuntimeError("close failed")
    fake_libvirt.openReadOnly.return_value = conn
    with patch.dict("sys.modules", {"libvirt": fake_libvirt}):
        assert probe._can_access_libvirt() is True
    conn.close.assert_called_once()


def test_libvirt_probe_single_flight_skips_when_previous_hung():
    """If a previous probe worker is still hung, don't spawn another (caps the
    leaked-thread count at one for a wedged libvirt stack)."""
    probe = _probe_obj({})
    hung = MagicMock()
    hung.is_alive.return_value = True
    probe._libvirt_probe_thread = hung
    fake_libvirt = MagicMock()
    with patch.dict("sys.modules", {"libvirt": fake_libvirt}):
        assert probe._can_access_libvirt() is False
    fake_libvirt.openReadOnly.assert_not_called()
    assert (
        probe._current_reason == "libvirt probe still running (previous attempt hung)"
    )


def test_libvirt_probe_clears_thread_handle_on_success():
    """A completed probe clears the in-flight handle so the next probe can run."""
    probe = _probe_obj({})
    probe._libvirt_probe_thread = None
    fake_libvirt = MagicMock()
    fake_libvirt.openReadOnly.return_value = MagicMock()
    with patch.dict("sys.modules", {"libvirt": fake_libvirt}):
        assert probe._can_access_libvirt() is True
    assert probe._libvirt_probe_thread is None


def test_libvirt_probe_times_out():
    probe = _probe_obj({})
    release = threading.Event()
    fake_libvirt = MagicMock()

    def blocking_open(uri):
        release.wait(2)  # block past the (patched, tiny) probe timeout
        return MagicMock()

    fake_libvirt.openReadOnly.side_effect = blocking_open
    try:
        with patch.dict("sys.modules", {"libvirt": fake_libvirt}), patch.object(
            perm, "LIBVIRT_PROBE_TIMEOUT", 0.05
        ):
            assert probe._can_access_libvirt() is False
        assert probe._current_reason == "libvirt probe timed out"
    finally:
        release.set()  # let the abandoned daemon worker finish
