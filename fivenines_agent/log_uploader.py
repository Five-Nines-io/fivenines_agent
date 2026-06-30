"""Dedicated worker thread that uploads log-capture bundles off the collection loop.

The agent has two pre-existing transport paths that both block something:
  - /collect runs on the Synchronizer thread (drains the metric queue),
  - /packages POSTs synchronously on the MAIN collection loop (blocks the tick).

A log bundle is larger and triggered during incidents, exactly when the host is
already unhappy. Posting it on either path would stall metric collection (and the
systemd watchdog) or the /collect+config sync. So log uploads get their OWN thread
and their OWN bounded queue:

    main thread            log_queue (bounded)        LogUploader thread
    capture_id nonce  -->  [job, job, ...]      -->   build_fn(job) -> send_fn(bundle)
    enqueues a JOB         drop-oldest, logged        journalctl + redact + digest, POST /logs

build_fn(job) runs the capture (Brique A: bounded retroactive journalctl, redaction,
enriched digest) and returns a bundle dict, or None to skip (capture failed / nothing
to send). send_fn(bundle) POSTs to /logs and returns truthy on success.

Each job is fully isolated: a build or send failure logs and moves on, never killing
the thread or starving later jobs.
"""

from threading import Event, Thread

from fivenines_agent.debug import log


class LogUploader(Thread):
    def __init__(self, queue, build_fn, send_fn):
        Thread.__init__(self)
        self._stop_event = Event()
        self.queue = queue
        self.build_fn = build_fn
        self.send_fn = send_fn

    def run(self):
        while not self._stop_event.is_set():
            job = self.queue.get()
            try:
                # None is the shutdown sentinel pushed by Agent._cleanup, mirroring
                # the Synchronizer drain. Break before doing any work.
                if job is None:
                    break
                self._process(job)
            finally:
                self.queue.task_done()

    def _process(self, job):
        # Per-job isolation: one bad capture must not kill the uploader thread
        # (registry-collector-needs-per-item-isolation learning, applied to the
        # async path).
        try:
            bundle = self.build_fn(job)
        except Exception as e:
            log(f"LogUploader: capture build failed for {job!r}: {e}", "error")
            return
        if bundle is None:
            log("LogUploader: capture produced no bundle, skipping", "debug")
            return
        try:
            if self.send_fn(bundle):
                log("LogUploader: bundle uploaded", "info")
            else:
                log("LogUploader: bundle upload failed, dropping", "error")
        except Exception as e:
            log(f"LogUploader: send failed: {e}", "error")

    def stop(self):
        self._stop_event.set()
