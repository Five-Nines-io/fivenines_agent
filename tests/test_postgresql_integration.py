"""Opt-in integration test for the PostgreSQL collector against a REAL server.

Skipped unless RUN_PG_INTEGRATION is set. This is the only test that exercises
the real pg8000 socket connection, SCRAM authentication, and live pg_stat_*
queries -- the path the mocked unit tests cannot cover. Pointed at the built
binary's environment, it also proves the frozen bundle ships pg8000 + scramp
(per the build-script hidden-imports).

Run against a local or containerized PostgreSQL, e.g.:

    docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16
    RUN_PG_INTEGRATION=1 PG_PASSWORD=postgres \\
        poetry run pytest tests/test_postgresql_integration.py -v
"""

import os

import pytest

from fivenines_agent.postgresql import postgresql_metrics


pytestmark = pytest.mark.skipif(
    not os.environ.get("RUN_PG_INTEGRATION"),
    reason="set RUN_PG_INTEGRATION=1 to run against a real PostgreSQL",
)


def _conn_kwargs():
    return {
        "host": os.environ.get("PG_HOST", "localhost"),
        "port": int(os.environ.get("PG_PORT", "5432")),
        "user": os.environ.get("PG_USER", "postgres"),
        "password": os.environ.get("PG_PASSWORD"),
        "database": os.environ.get("PG_DATABASE", "postgres"),
    }


def test_real_postgres_is_reachable_with_metrics():
    """Connect for real (SCRAM when a password is set) and collect metrics."""
    result = postgresql_metrics(**_conn_kwargs())
    assert result is not None
    assert result["reachable"] is True, result
    assert "version" in result
    assert "connections" in result
    assert "is_replica" in result
    assert isinstance(result.get("databases", []), list)


def test_real_postgres_unreachable_on_closed_port():
    """A definitely-closed port yields a structured unreachable status."""
    result = postgresql_metrics(host="127.0.0.1", port=1)
    assert result["reachable"] is False
    assert result["error"] in {"connection_refused", "timeout", "unreachable"}
