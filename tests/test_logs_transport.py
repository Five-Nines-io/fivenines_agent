"""Coverage for the small transport seams: Synchronizer.send_logs and the
Brique A capture stub (build_capture_bundle, implemented in a follow-up chunk)."""

from unittest.mock import MagicMock

from fivenines_agent.logs import build_capture_bundle
from fivenines_agent.synchronization_queue import SynchronizationQueue
from fivenines_agent.synchronizer import Synchronizer


def test_build_capture_bundle_stub_returns_none():
    # The Brique A capture is a follow-up chunk; the seam returns None for now so
    # the LogUploader simply skips (no bundle to send).
    assert build_capture_bundle({"capture_id": "x", "unit": "nginx.service"}) is None


def test_send_logs_posts_to_logs_endpoint():
    s = Synchronizer("tok", SynchronizationQueue())
    s._post = MagicMock(return_value={"ok": True})
    assert s.send_logs({"capture_id": "x"}) == {"ok": True}
    s._post.assert_called_once_with("/logs", {"capture_id": "x"})
