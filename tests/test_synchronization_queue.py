"""Tests for SynchronizationQueue, the bounded buffer between the collection
loop and the Synchronizer thread.

put() never blocks: past the bound it drops the OLDEST payload so an API
outage cannot grow the agent's memory, and clear() empties the backlog at
shutdown without leaving join() waiting on tasks nobody will finish.
"""

from unittest.mock import patch

from fivenines_agent.synchronization_queue import SynchronizationQueue


def _drain(queue):
    items = []
    while not queue.empty():
        items.append(queue.get_nowait())
    return items


def test_put_below_the_bound_keeps_every_payload_in_order():
    queue = SynchronizationQueue(maxsize=3)
    with patch("fivenines_agent.synchronization_queue.log") as mock_log:
        for i in range(3):
            queue.put(i)
    mock_log.assert_not_called()
    assert queue.unfinished_tasks == 3
    assert _drain(queue) == [0, 1, 2]


def test_put_past_the_bound_drops_the_oldest_payload():
    queue = SynchronizationQueue(maxsize=2)
    with patch("fivenines_agent.synchronization_queue.log") as mock_log:
        for i in range(6):
            queue.put(i)

    # The check runs before each insert and drops only once the queue holds
    # MORE than maxsize, so the backlog settles at maxsize + 1 entries: the
    # newest ones, oldest first.
    assert queue.qsize() == 3
    # Every drop also retires the dropped payload's task, so join() still
    # waits only for what is actually queued.
    assert queue.unfinished_tasks == 3
    assert _drain(queue) == [3, 4, 5]
    assert mock_log.call_count == 3
    assert mock_log.call_args.args == ("Queue size too big: 3. Dropping oldest data",)


def test_put_wakes_a_waiting_consumer():
    queue = SynchronizationQueue()
    queue.put(b"payload")
    # get() with a timeout goes through not_empty: the put must have notified
    # it, and the item must be there.
    assert queue.get(timeout=1) == b"payload"


def test_clear_empties_the_backlog_and_releases_join():
    queue = SynchronizationQueue(maxsize=10)
    for i in range(4):
        queue.put(i)

    queue.clear()

    assert queue.empty()
    assert queue.unfinished_tasks == 0
    # With every task retired, join() returns at once instead of blocking
    # the shutdown path.
    queue.join()
    # The queue stays usable after a clear (the shutdown sentinel is put
    # right after it).
    queue.put(None)
    assert queue.get_nowait() is None
