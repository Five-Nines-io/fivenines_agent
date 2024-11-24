from queue import Queue
from fivenines_agent.env import debug_mode

class SynchronizationQueue(Queue):
    def __init__(self, maxsize=100):
        Queue.__init__(self, maxsize)

    def put(self, data):
        with self.mutex:
            if self._qsize() > self.maxsize:
                if debug_mode():
                    print(f'Queue size too big: {self._qsize()}. Dropping oldest data')
                super()._get()
                self.unfinished_tasks -= 1

            super()._put(data)
            self.unfinished_tasks += 1
            self.not_empty.notify()

    def clear(self):
        with self.mutex:
            self.queue.clear()
            self.unfinished_tasks = 0
            self.not_full.notify() 
            self.all_tasks_done.notify_all()
