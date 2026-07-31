"""Shared worker loop for the agent's out-of-band upload threads.

The agent has two pre-existing transport paths that both block something:
  - /collect runs on the Synchronizer thread (drains the metric queue),
  - /packages POSTs synchronously on the MAIN collection loop (blocks the tick).

Anything bigger or slower than a metric payload therefore gets its OWN thread and
its OWN bounded queue, so a slow upload can never stall metric collection or the
systemd watchdog:

    main thread              queue (bounded)          uploader thread
    enqueues a JOB      -->  [job, job, ...]     -->  build_fn(job) -> send_fn(x)

build_fn(job) does the expensive work and returns something to send, or None to
skip (nothing to send / try again later). send_fn(x) performs the upload and
returns truthy on success.

Each job is fully isolated: a build or send failure logs and moves on, never
killing the thread or starving later jobs. Every terminal outcome calls exactly
one of on_success / on_failure with the job's id, which is how a coordinator
learns whether to retire the work item or release it for retry.

Subclasses supply only their vocabulary (``label``, ``job_id_key`` and the noun
used in log lines); the drain / isolation / shutdown logic lives here once.
Concrete users: LogUploader (incident log bundles -> /logs) and
ImageInventoryUploader (image package inventories -> /image_packages).
"""

from threading import Event, Thread

from fivenines_agent.debug import log


class QueueUploader(Thread):
    # Prefix for every log line, so operators can grep one worker's output.
    label = "QueueUploader"
    # Key holding the job's identity, passed back to on_success / on_failure.
    job_id_key = "id"
    # Noun for the thing build_fn produces, used in log lines ("bundle",
    # "inventory", ...).
    payload_noun = "payload"

    def __init__(self, queue, build_fn, send_fn, on_success=None, on_failure=None):
        Thread.__init__(self)
        self._stop_event = Event()
        self.queue = queue
        self.build_fn = build_fn
        self.send_fn = send_fn
        # Called with the job's id on a terminal outcome, so a coordinator can
        # mark it done (no replay) or release it for retry.
        self._on_success = on_success or (lambda job_id: None)
        self._on_failure = on_failure or (lambda job_id: None)

    def run(self):
        while not self._stop_event.is_set():
            job = self.queue.get()
            try:
                # None is the shutdown sentinel pushed by Agent._cleanup,
                # mirroring the Synchronizer drain. Break before doing any work.
                if job is None:
                    break
                self._process(job)
            finally:
                self.queue.task_done()

    def _job_id(self, job):
        return job.get(self.job_id_key) if isinstance(job, dict) else None

    def _process(self, job):
        # Per-job isolation: one bad job must not kill the uploader thread
        # (registry-collector-needs-per-item-isolation learning, applied to the
        # async path). Every terminal outcome signals the coordinator exactly once.
        job_id = self._job_id(job)
        try:
            payload = self.build_fn(job)
        except Exception as e:
            log(f"{self.label}: build failed for {job_id!r}: {e}", "error")
            self._on_failure(job_id)
            return
        if payload is None:
            log(
                f"{self.label}: no {self.payload_noun} for {job_id!r}, skipping",
                "debug",
            )
            self._on_failure(job_id)
            return
        try:
            ok = self.send_fn(payload)
        except Exception as e:
            log(f"{self.label}: send failed for {job_id!r}: {e}", "error")
            self._on_failure(job_id)
            return
        if ok:
            log(f"{self.label}: {self.payload_noun} uploaded for {job_id!r}", "info")
            self._on_success(job_id)
        else:
            log(
                f"{self.label}: {self.payload_noun} upload failed for {job_id!r}",
                "error",
            )
            self._on_failure(job_id)

    def stop(self):
        self._stop_event.set()
