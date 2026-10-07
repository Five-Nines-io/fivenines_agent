"""Sanitation for customer-controlled values an API collector ships or logs.

The Proxmox VE backups block (#156) and the PBS collector read JSON from an
API the customer operates and forward parts of it: names, ids, job states,
error bodies. Every such string is untrusted on two paths, and this module is
the one implementation of both, so the two collectors cannot drift:

- the WIRE (``scrub_str`` / ``scrub_message``): UTF-8 with invalid sequences
  replaced, NUL deleted (Postgres refuses to store it), length-capped, and an
  error body additionally redacted, since an API error can echo a credential;
- the LOG (``log_safe``): redacted, with C0/C1 control characters collapsed to
  spaces so a newline in a hostile value cannot forge extra journal lines,
  and ASCII only (backslash escapes) so print() cannot raise on a stdout of
  any encoding: a Windows service's is the ANSI code page, and a lone
  surrogate breaks even UTF-8.

Both bound the input BEFORE the redaction regexes run over it: an unbounded
blob would otherwise turn redact() into a CPU sink on the watchdog-bounded
collection loop.
"""

from fivenines_agent.logs import redact

# Cap on one shipped field (an id, a name, a job state).
FIELD_MAX_LEN = 500

# Cap on an error message, on the wire and in a log line.
ERROR_MAX_LEN = 500

# Prefix bound applied to a raw message BEFORE redact() runs over it; the final
# ERROR_MAX_LEN cap trims the redacted result. Same posture as the ceph stderr
# envelope.
ERROR_PRE_REDACT_MAX_LEN = 2000

# C0 + C1 control characters (incl. newlines) mapped to a space.
_LOG_CONTROL_TO_SPACE = {
    c: ord(" ") for c in list(range(0x20)) + [0x7F] + list(range(0x80, 0xA0))
}


def scrub_str(value, max_len=FIELD_MAX_LEN):
    """Make a customer-controlled value safe for the wire: UTF-8 with invalid
    sequences replaced, NUL deleted, capped.

    None stays None so "the API reported no value" survives as null.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    # Bound the work BEFORE the encode/decode/replace pass: a pathological
    # multi-MB field from a hostile response must not be fully re-encoded on
    # the watchdog loop to return max_len chars. Slicing a str is by code point,
    # so a generous pre-slice yields the same result for any real (short) value;
    # NUL removal only shrinks, so the final [:max_len] still holds.
    cleaned = (
        value[:max_len]
        .encode("utf-8", errors="replace")
        .decode("utf-8", errors="replace")
    )
    return cleaned.replace("\x00", "")[:max_len]


def scrub_message(message):
    """An error message for the wire: prefix-bounded, redacted, scrubbed."""
    return scrub_str(redact(str(message)[:ERROR_PRE_REDACT_MAX_LEN]), ERROR_MAX_LEN)


def log_safe(value):
    """Make a customer-controlled value safe to interpolate into a log line:
    redact secrets (an API error body can echo a credential) and collapse
    control characters so a newline in a value cannot forge journal lines.
    """
    bounded = str(value)[:ERROR_PRE_REDACT_MAX_LEN]
    line = redact(bounded).translate(_LOG_CONTROL_TO_SPACE)
    # print() raises on a character its stdout cannot encode -- a lone
    # surrogate (a JSON "\udc80" escape) on UTF-8, a U+FFFD or any CJK text
    # on a Windows service's cp1252 -- inside the collector, sinking its tick.
    line = line.encode("ascii", errors="backslashreplace").decode("ascii")
    return line[:ERROR_MAX_LEN]


def as_int(value):
    """int() that answers None instead of raising on anything non-numeric.

    Bools are refused: True would otherwise read as id 1.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def as_bool(value):
    """Proxmox APIs spell booleans as 0/1 ints, "0"/"1" strings or JSON bools."""
    if isinstance(value, str):
        return value.strip() not in ("", "0")
    return bool(value)
