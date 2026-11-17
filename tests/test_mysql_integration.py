"""Opt-in integration tests for the MySQL collector against a REAL server.

Skipped unless RUN_MYSQL_INTEGRATION is set. tests/test_mysql.py drives the
real PyMySQL against an in-process fake server; these run the collector
against MySQL or MariaDB itself: the handshake and authentication plugin the
server really picks (caching_sha2_password on MySQL 8+, with TLS PREFERRED),
and the statements' real columns.

Run against a local or containerized server, e.g.:

    docker run --rm -d -p 3306:3306 -e MYSQL_ROOT_PASSWORD=secret mysql:8.4
    RUN_MYSQL_INTEGRATION=1 MYSQL_PASSWORD=secret \\
        poetry run pytest tests/test_mysql_integration.py -v

The same with mariadb:11.8 (MARIADB_ROOT_PASSWORD). A dedicated MYSQL_USER
needs REPLICATION CLIENT (MySQL) or SLAVE MONITOR (MariaDB 10.5+) for the
is_replica assertion. MYSQL_SOCKET adds the
unix-socket path; MYSQL_UTF8_USER / MYSQL_UTF8_PASSWORD an account whose
password holds non-ASCII characters (CREATE USER ... IDENTIFIED BY over a
UTF-8 client), which the collector must send as UTF-8.
"""

import os

import pytest

from fivenines_agent.mysql import mysql_metrics

pytestmark = pytest.mark.skipif(
    not os.environ.get("RUN_MYSQL_INTEGRATION"),
    reason="set RUN_MYSQL_INTEGRATION=1 to run against a real MySQL/MariaDB",
)


def _tcp():
    return {
        "host": os.environ.get("MYSQL_HOST", "127.0.0.1"),
        "port": int(os.environ.get("MYSQL_PORT", "3306")),
        "user": os.environ.get("MYSQL_USER", "root"),
        "password": os.environ.get("MYSQL_PASSWORD"),
    }


def _assert_metrics(result):
    assert result["reachable"] is True, result
    for key in ("connections", "queries", "uptime", "max_connections", "version"):
        assert key in result, (key, result)
    assert "is_replica" in result, result


def test_real_server_over_tcp_is_reachable_with_metrics():
    _assert_metrics(mysql_metrics(**_tcp()))


def test_real_server_twice_in_a_row():
    """A second collection after the first (caching_sha2_password's fast
    path once the server cached the password)."""
    _assert_metrics(mysql_metrics(**_tcp()))
    _assert_metrics(mysql_metrics(**_tcp()))


def test_real_server_wrong_password_is_auth_failed():
    result = mysql_metrics(**{**_tcp(), "password": "definitely-not-it"})
    assert result["reachable"] is False
    assert result["error"] == "auth_failed", result
    assert result["error_detail"].startswith("ERROR 1045: "), result


@pytest.mark.skipif(not os.environ.get("MYSQL_SOCKET"), reason="set MYSQL_SOCKET")
def test_real_server_over_its_unix_socket():
    config = {**_tcp(), "socket": os.environ["MYSQL_SOCKET"]}
    _assert_metrics(mysql_metrics(**config))


@pytest.mark.skipif(
    not os.environ.get("MYSQL_UTF8_USER"), reason="set MYSQL_UTF8_USER/PASSWORD"
)
def test_real_server_non_ascii_password():
    config = {
        **_tcp(),
        "user": os.environ["MYSQL_UTF8_USER"],
        "password": os.environ["MYSQL_UTF8_PASSWORD"],
    }
    result = mysql_metrics(**config)
    assert result["reachable"] is True, result
