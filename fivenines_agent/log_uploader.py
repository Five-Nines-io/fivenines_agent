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

The drain / per-job isolation / shutdown logic itself lives in
queue_uploader.QueueUploader, shared with the image-inventory uploader; this
class supplies only the log vocabulary and the job-id key.
"""

from fivenines_agent.queue_uploader import QueueUploader


class LogUploader(QueueUploader):
    label = "LogUploader"
    job_id_key = "capture_id"
    payload_noun = "bundle"
