"""Coverage for the Synchronizer.send_logs transport seam.

Brique A (build_capture_bundle) and its helpers are covered in test_logs.py."""

from unittest.mock import MagicMock

from fivenines_agent.synchronization_queue import SynchronizationQueue
from fivenines_agent.synchronizer import Synchronizer


def test_send_logs_posts_to_logs_endpoint():
    s = Synchronizer("tok", SynchronizationQueue())
    s._post = MagicMock(return_value={"ok": True})
    assert s.send_logs({"capture_id": "x"}) == {"ok": True}
    s._post.assert_called_once_with("/logs", {"capture_id": "x"})
