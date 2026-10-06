"""Opt-in integration test for the PostgreSQL collector against a REAL server.

Skipped unless RUN_PG_INTEGRATION is set. This is the only test that runs a
complete SCRAM exchange and live pg_stat_* queries against a real server --
the path the unit tests cannot cover (test_postgresql.py drives the real
pg8000 against an in-process fake server only as far as the SCRAM mechanism
offer). Pointed at the built binary's environment, it also proves the frozen
bundle ships pg8000 + scramp (per the build-script hidden-imports).

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


@pytest.mark.skipif(
    not os.environ.get("PG_PASSWORD"),
    reason="set PG_PASSWORD: needs a server that demands a password",
)
def test_real_postgres_scram_without_password_is_auth_failed(monkeypatch, tmp_path):
    """A stock PostgreSQL 14+ demands SCRAM-SHA-256 on a TCP host line, as the
    docker recipe above does. With no password in config, PGPASSWORD or
    .pgpass the collector reports auth_failed; agents up to 1.20.4 sent the
    generic "'NoneType' object has no attribute 'decode'" error instead."""
    monkeypatch.delenv("PGPASSWORD", raising=False)
    monkeypatch.setenv("PGPASSFILE", str(tmp_path / "does-not-exist.pgpass"))
    kwargs = _conn_kwargs()
    kwargs["password"] = None
    assert postgresql_metrics(**kwargs) == {"reachable": False, "error": "auth_failed"}


def test_real_postgres_unreachable_on_closed_port():
    """A definitely-closed port yields a structured unreachable status."""
    result = postgresql_metrics(host="127.0.0.1", port=1)
    assert result["reachable"] is False
    assert result["error"] in {"connection_refused", "timeout", "unreachable"}
