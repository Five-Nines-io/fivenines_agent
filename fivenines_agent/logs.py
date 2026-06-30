"""Log signal collection (Brique C) and incident capture (Brique A).

The Brique A capture (retroactive `journalctl` slice WITH a timeout, secret/PII
redaction, enriched digest) is implemented in a follow-up chunk. `build_capture_bundle`
is the seam the LogUploader thread calls per capture job; it returns the bundle dict
(echoing job["capture_id"] for the /logs ack) or None to skip.

For now it returns None so the transport + nonce plumbing ships and is tested
independently of journald.
"""

from fivenines_agent.debug import log


def build_capture_bundle(job):
    # TODO(brique-a): journalctl -u <job['unit']> --since <job['since']> with a
    # subprocess timeout (timeout-the-data-path learning), redact secrets/PII,
    # build the enriched digest (counts + redacted excerpts), cap at
    # job['max_bytes'], and return the bundle echoing job['capture_id'].
    log(f"build_capture_bundle: not yet implemented for {job!r}", "debug")
    return None
