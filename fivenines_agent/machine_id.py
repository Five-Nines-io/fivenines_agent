"""Stable per-agent machine identity.

The agent generates a UUID on first run and persists it next to the TOKEN
file in the config directory. The same value is returned on every later run,
which lets the server treat re-enrollment of one machine as idempotent
instead of creating a duplicate host (see fivenines_server #354).

Resolution order:

    CONFIG_DIR/MACHINE_ID holds a valid UUID  ->  reuse it
    otherwise                                 ->  generate a uuid4, persist it
    cannot persist                            ->  return None

Returning None is deliberate: an agent that cannot persist a stable id sends
no machine_id, and the server falls back to creating a new host per
enrollment (Phase 1 behavior). A per-run UUID would be worse -- it would look
like a brand-new machine on every restart.
"""

import os
import uuid

from fivenines_agent.debug import log
from fivenines_agent.env import config_dir

MACHINE_ID_FILENAME = "MACHINE_ID"


def _valid_uuid(value):
    """True when value is a well-formed UUID string."""
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def _read_persisted_id(path):
    """Return the persisted machine id when the file holds a valid UUID."""
    try:
        with open(path, "r") as f:
            content = f.read().strip()
    except FileNotFoundError:
        return None
    except OSError as e:
        log(f"Could not read machine id file {path}: {e}", "error")
        return None

    if _valid_uuid(content):
        return content

    log(f"Machine id file {path} is invalid, regenerating", "warn")
    return None


def _persist_id(path, value):
    """Write value to path with owner-only permissions. True on success."""
    try:
        with open(path, "w") as f:
            f.write(value)
        os.chmod(path, 0o600)
        return True
    except OSError as e:
        log(
            f"Could not persist machine id to {path}: {e}. "
            "Sending no machine_id this run.",
            "warn",
        )
        return False


def get_machine_id():
    """Return a stable per-agent UUID, or None when it cannot be persisted.

    Never raises: any unexpected failure degrades to None so machine id
    resolution can never stop the agent from starting.
    """
    try:
        path = os.path.join(config_dir(), MACHINE_ID_FILENAME)

        persisted = _read_persisted_id(path)
        if persisted is not None:
            log("machine_id resolved from persisted file", "info")
            return persisted

        new_id = str(uuid.uuid4())
        if _persist_id(path, new_id):
            log("machine_id generated and persisted", "info")
            return new_id

        return None
    except Exception as e:
        log(f"Unexpected error resolving machine id: {e}", "error")
        return None
