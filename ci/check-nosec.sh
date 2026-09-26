#!/bin/sh
# Enforce the Bandit policy (CONTRIBUTING.md, "Findings and suppressions"):
#   - [tool.bandit] in pyproject.toml is exactly the documented policy, and no
#     other Bandit config exists, so the shell checks (B602, B604, B605) cannot
#     be switched off by a quiet config edit -- a new skip, a `tests` allowlist,
#     an `exclude_dirs` entry or a `.bandit` file alike;
#   - every suppression names the one test it silences and says why, as
#     `# nosec B110  # <reason>`;
#   - nothing is suppressed wholesale.
#
# Usage: sh ci/check-nosec.sh [bandit command] [directory]
#   (defaults: bandit, fivenines_agent). Run from the repository root.
# bandit.yml runs it on every pull request, and against deliberately bad input
# to prove it still fails; `make lint` runs the same script locally.
set -eu

BANDIT="${1:-bandit}"
TARGET="${2:-fivenines_agent}"
status=0

# 0. The config is the documented policy and nothing else.
if ! python3 - <<'PY'
import sys

try:
    import tomllib
except ModuleNotFoundError:
    sys.exit("ERROR: checking [tool.bandit] needs Python 3.11+ (tomllib).")

with open("pyproject.toml", "rb") as f:
    table = tomllib.load(f).get("tool", {}).get("bandit")
expected = {"skips": ["B404", "B603", "B607"]}
if table != expected:
    sys.exit(
        "ERROR: [tool.bandit] in pyproject.toml is %r, expected %r. That table is"
        " the security policy: change it together with CONTRIBUTING.md and this"
        " script." % (table, expected)
    )
PY
then
    status=1
fi

# 0b. No other Bandit config. Bandit also reads a `.bandit` INI file found in
# the scanned tree, and merges its skips even when -c names pyproject.toml.
stray=$( { find "$TARGET" -name .bandit; if [ -e .bandit ]; then echo ./.bandit; fi; } 2>/dev/null || true)
if [ -n "$stray" ]; then
    echo "ERROR: a .bandit file would change the Bandit policy outside pyproject.toml:"
    echo "$stray"
    status=1
fi

# 1. Shape: one named test, then the reason as a second comment.
bad=$(grep -rnE '#[[:space:]]*nosec' "$TARGET" | grep -vE '  # nosec B[0-9]{3}  # [^ ]' || true)
if [ -n "$bad" ]; then
    echo "ERROR: suppressions must read '# nosec BXXX  # <reason>':"
    echo "$bad"
    status=1
fi

# 2. Nothing blanket. A well-formed comment naming a test that does not exist
# (`# nosec B999  # ...`) passes the shape check, yet Bandit treats it as a bare
# `# nosec` and silences every test on the line. Only Bandit knows its own test
# IDs, so ask it: its `nosec` counter counts exactly the blanket suppressions.
# $BANDIT is word-split on purpose: it may be `poetry run bandit`.
# shellcheck disable=SC2086
blanket=$($BANDIT -c pyproject.toml -r "$TARGET" -q -f json 2>/dev/null \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["metrics"]["_totals"]["nosec"])')
if [ "$blanket" != "0" ]; then
    echo "ERROR: ${blanket} finding(s) silenced by a blanket suppression (a bare '# nosec'"
    echo "or one naming an unknown test ID). Run bandit to see Bandit's warning for it."
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "Bandit policy OK: config as documented; each suppression names a real test and a reason."
fi
exit "$status"
