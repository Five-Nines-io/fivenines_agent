"""Tests for fivenines_agent.mysql module (CLI shell-out collector).

The collector shells out to the `mysql`/`mariadb` client, so tests mock at two
seams:
  - fivenines_agent.mysql.subprocess.run  -> fake CompletedProcess per query
  - fivenines_agent.mysql.shutil.which    -> pretend the client is installed

No real MySQL/MariaDB is needed. Fixtures are inline (this repo has no
tests/fixtures dir / conftest for collectors). The acceptance criterion
"verified on MySQL 8 AND MariaDB" is met by the two full-flow tests plus the
parametrized parser/replication cases.
"""

import subprocess
from unittest.mock import patch

import pytest

from fivenines_agent.mysql import (
    _add_status_metrics,
    _add_variable_metrics,
    _buffer_pool_hit_ratio,
    _buffer_pool_usage_pct,
    _build_replication,
    _classify_error,
    _clean_stderr,
    _failure,
    _first,
    _get_replication,
    _parse_status,
    _parse_vertical,
    _resolve_binary,
    _run_mysql,
    _to_int,
    _yes,
    mysql_metrics,
)


MY = "fivenines_agent.mysql"


# ---------------------------------------------------------------------------
# Inline fixtures: SHOW GLOBAL STATUS / VARIABLES (tabular) and replica
# (vertical). STATUS/VARIABLES key sets are identical on MySQL and MariaDB;
# only the replica command/columns diverge.
# ---------------------------------------------------------------------------

MYSQL8_STATUS = (
    "Threads_connected\t42\n"
    "Queries\t1234567\n"
    "Slow_queries\t12\n"
    "Aborted_connects\t3\n"
    "Uptime\t864000\n"
    "Innodb_buffer_pool_reads\t1300\n"
    "Innodb_buffer_pool_read_requests\t1000000\n"
    "Innodb_buffer_pool_pages_total\t1000\n"
    "Innodb_buffer_pool_pages_free\t358\n"
)

MYSQL8_VARS = "max_connections\t151\nversion\t8.0.36\n"

# MySQL 8.0.22+ vertical replica output.
MYSQL8_REPLICA = (
    "*************************** 1. row ***************************\n"
    "             Replica_IO_State: Waiting for source to send event\n"
    "                  Source_Host: 10.0.0.1\n"
    "        Seconds_Behind_Source: 5\n"
    "           Replica_IO_Running: Yes\n"
    "          Replica_SQL_Running: Yes\n"
)

# MariaDB: read_requests == 0 exercises the div/0 guard (hit ratio -> 100.0);
# equal total/free -> 0.0 usage.
MARIADB_STATUS = (
    "Threads_connected\t7\n"
    "Queries\t555\n"
    "Slow_queries\t0\n"
    "Aborted_connects\t1\n"
    "Uptime\t3600\n"
    "Innodb_buffer_pool_reads\t0\n"
    "Innodb_buffer_pool_read_requests\t0\n"
    "Innodb_buffer_pool_pages_total\t500\n"
    "Innodb_buffer_pool_pages_free\t500\n"
)

MARIADB_VARS = "max_connections\t100\nversion\t10.11.6-MariaDB\n"

# MariaDB / older-MySQL vertical replica output (SHOW SLAVE STATUS).
MARIADB_REPLICA = (
    "*************************** 1. row ***************************\n"
    "                Slave_IO_State: Waiting for master to send event\n"
    "                   Master_Host: 10.0.0.2\n"
    "         Seconds_Behind_Master: 0\n"
    "              Slave_IO_Running: Yes\n"
    "             Slave_SQL_Running: Yes\n"
)

# Broken replication: NULL lag + SQL thread stopped.
REPLICA_NULL_LAG = (
    "*************************** 1. row ***************************\n"
    "        Seconds_Behind_Source: NULL\n"
    "           Replica_IO_Running: Yes\n"
    "          Replica_SQL_Running: No\n"
)


def completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=["mysql"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def run_map(responses, default=("", "", 0)):
    """subprocess.run fake dispatching on the trailing -e SQL argument.

    responses maps a distinctive SQL substring -> (stdout, stderr, returncode).
    Order-independent: matches on the query text rather than call sequence.
    """

    def _fake(cmd, **kwargs):
        sql = cmd[-1]
        for needle, resp in responses.items():
            if needle in sql:
                return completed(*resp)
        return completed(*default)

    return _fake


def run_metrics(responses, **kwargs):
    """Run mysql_metrics with the client 'installed' and subprocess mocked."""
    with patch(f"{MY}.shutil.which", return_value="/usr/bin/mysql"), patch(
        f"{MY}.subprocess.run", side_effect=run_map(responses)
    ):
        return mysql_metrics(**kwargs)


# ---------------------------------------------------------------------------
# _resolve_binary: mysql preferred, mariadb fallback, absent -> None
# ---------------------------------------------------------------------------


def test_resolve_binary_prefers_mysql():
    with patch(f"{MY}.shutil.which", side_effect=lambda c: "/usr/bin/mysql"):
        assert _resolve_binary() == "mysql"


def test_resolve_binary_falls_back_to_mariadb():
    def which(candidate):
        return "/usr/bin/mariadb" if candidate == "mariadb" else None

    with patch(f"{MY}.shutil.which", side_effect=which):
        assert _resolve_binary() == "mariadb"


def test_resolve_binary_none_when_absent():
    with patch(f"{MY}.shutil.which", return_value=None):
        assert _resolve_binary() is None


# ---------------------------------------------------------------------------
# _classify_error: stable, backend-facing categories
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stderr,expected",
    [
        ("ERROR 1045 (28000): Access denied for user 'root'@'localhost'", "auth_failed"),
        ("access denied", "auth_failed"),
        ("ERROR 2002 (HY000): Can't connect to local MySQL server", "connection_refused"),
        ("ERROR 2003 (HY000): Can't connect to MySQL server on 'db'", "connection_refused"),
        ("Connection refused", "connection_refused"),
        ("ERROR 2005 (HY000): Unknown MySQL server host 'nope' (2)", "unreachable"),
        ("some other failure", "error"),
        ("", "error"),
        (None, "error"),
    ],
)
def test_classify_error(stderr, expected):
    assert _classify_error(stderr) == expected


# ---------------------------------------------------------------------------
# _clean_stderr: drop the MYSQL_PWD deprecation warning noise
# ---------------------------------------------------------------------------


def test_clean_stderr_empty():
    assert _clean_stderr("") == ""
    assert _clean_stderr(None) == ""


def test_clean_stderr_filters_password_warning():
    stderr = (
        "mysql: [Warning] Using a password on the command line interface "
        "can be insecure.\n"
        "ERROR 2002 (HY000): Can't connect to local MySQL server\n"
    )
    cleaned = _clean_stderr(stderr)
    assert "Warning" not in cleaned
    assert "Can't connect" in cleaned


def test_clean_stderr_keeps_real_errors():
    assert _clean_stderr("ERROR 1045: Access denied") == "ERROR 1045: Access denied"


# ---------------------------------------------------------------------------
# _run_mysql: command construction + result classification
# ---------------------------------------------------------------------------


def _conn(**over):
    base = {
        "host": "localhost",
        "port": 3306,
        "user": "root",
        "password": None,
        "database": None,
        "socket": None,
    }
    base.update(over)
    return base


def test_run_mysql_tcp_command_and_success():
    with patch(f"{MY}.subprocess.run", return_value=completed("out\t1", "")) as run:
        stdout, err, stderr = _run_mysql("mysql", "SHOW GLOBAL STATUS", _conn())
    assert (stdout, err) == ("out\t1", None)
    cmd = run.call_args.args[0]
    assert cmd[:3] == ["mysql", "-u", "root"]
    assert "-h" in cmd and "localhost" in cmd
    assert "-P" in cmd and "3306" in cmd
    assert cmd[-4:] == ["-N", "-B", "-e", "SHOW GLOBAL STATUS"]


def test_run_mysql_socket_ignores_host_port():
    with patch(f"{MY}.subprocess.run", return_value=completed("", "")) as run:
        _run_mysql("mysql", "SHOW GLOBAL STATUS", _conn(socket="/tmp/mysql.sock"))
    cmd = run.call_args.args[0]
    assert "--socket" in cmd and "/tmp/mysql.sock" in cmd
    assert "-h" not in cmd and "-P" not in cmd


def test_run_mysql_includes_database_when_set():
    with patch(f"{MY}.subprocess.run", return_value=completed("", "")) as run:
        _run_mysql("mysql", "SELECT 1", _conn(database="appdb"))
    cmd = run.call_args.args[0]
    assert "-D" in cmd and "appdb" in cmd


def test_run_mysql_vertical_omits_batch_flags():
    with patch(f"{MY}.subprocess.run", return_value=completed("", "")) as run:
        _run_mysql("mysql", "SHOW REPLICA STATUS\\G", _conn(), vertical=True)
    cmd = run.call_args.args[0]
    assert "-N" not in cmd and "-B" not in cmd


def test_run_mysql_sets_mysql_pwd_env_when_password():
    with patch(f"{MY}.subprocess.run", return_value=completed("", "")) as run:
        _run_mysql("mysql", "SELECT 1", _conn(password="s3cret"))
    env = run.call_args.kwargs["env"]
    assert env["MYSQL_PWD"] == "s3cret"


def test_run_mysql_no_mysql_pwd_env_when_no_password():
    with patch(f"{MY}.subprocess.run", return_value=completed("", "")) as run:
        _run_mysql("mysql", "SELECT 1", _conn(password=None))
    env = run.call_args.kwargs["env"]
    assert "MYSQL_PWD" not in env


def test_run_mysql_nonzero_returncode_classifies_error():
    stderr = "ERROR 1045 (28000): Access denied for user 'root'@'localhost'"
    with patch(f"{MY}.subprocess.run", return_value=completed("", stderr, 1)):
        stdout, err, out_stderr = _run_mysql("mysql", "SHOW GLOBAL STATUS", _conn())
    assert stdout is None
    assert err == "auth_failed"
    assert out_stderr == stderr


def test_run_mysql_timeout():
    with patch(
        f"{MY}.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="mysql", timeout=10),
    ):
        assert _run_mysql("mysql", "SELECT 1", _conn()) == (None, "timeout", "")


def test_run_mysql_missing_binary():
    with patch(f"{MY}.subprocess.run", side_effect=FileNotFoundError()):
        assert _run_mysql("mysql", "SELECT 1", _conn()) == (None, "client_missing", "")


def test_run_mysql_generic_oserror():
    with patch(f"{MY}.subprocess.run", side_effect=PermissionError("boom")):
        stdout, err, stderr = _run_mysql("mysql", "SELECT 1", _conn())
    assert (stdout, err) == (None, "error")
    assert "boom" in stderr


# ---------------------------------------------------------------------------
# Parsers + small helpers
# ---------------------------------------------------------------------------


def test_parse_status_tab_separated():
    parsed = _parse_status("Threads_connected\t42\nmalformed line\nUptime\t3600\n")
    assert parsed == {"Threads_connected": "42", "Uptime": "3600"}


def test_parse_status_empty():
    assert _parse_status("") == {}
    assert _parse_status(None) == {}


def test_parse_vertical_skips_separator_and_keeps_colons():
    text = (
        "*************************** 1. row ***************************\n"
        "        Seconds_Behind_Source: 5\n"
        "                   Last_Error: at 10:30:00 boom\n"
        "no colon here\n"
    )
    parsed = _parse_vertical(text)
    assert parsed["Seconds_Behind_Source"] == "5"
    assert parsed["Last_Error"] == "at 10:30:00 boom"
    assert "no colon here" not in parsed


def test_parse_vertical_empty():
    assert _parse_vertical("") == {}
    assert _parse_vertical(None) == {}


@pytest.mark.parametrize(
    "value,expected",
    [("42", 42), ("0", 0), ("NULL", None), ("", None), (None, None), ("x", None)],
)
def test_to_int(value, expected):
    assert _to_int(value) == expected


def test_first_returns_first_present_key():
    row = {"Slave_IO_Running": "Yes"}
    assert _first(row, "Replica_IO_Running", "Slave_IO_Running") == "Yes"
    assert _first(row, "Replica_IO_Running") is None


@pytest.mark.parametrize(
    "value,expected",
    [("Yes", True), ("yes", True), ("No", False), (" YES ", True), (None, False)],
)
def test_yes(value, expected):
    assert _yes(value) is expected


# ---------------------------------------------------------------------------
# InnoDB buffer-pool ratios (computed agent-side, div/0 guarded)
# ---------------------------------------------------------------------------


def test_hit_ratio_normal():
    status = {
        "Innodb_buffer_pool_reads": "1300",
        "Innodb_buffer_pool_read_requests": "1000000",
    }
    assert _buffer_pool_hit_ratio(status) == 99.87


def test_hit_ratio_zero_requests_guarded_to_100():
    status = {
        "Innodb_buffer_pool_reads": "0",
        "Innodb_buffer_pool_read_requests": "0",
    }
    assert _buffer_pool_hit_ratio(status) == 100.0


def test_hit_ratio_none_when_counters_absent():
    assert _buffer_pool_hit_ratio({}) is None


def test_usage_pct_normal():
    status = {
        "Innodb_buffer_pool_pages_total": "1000",
        "Innodb_buffer_pool_pages_free": "358",
    }
    assert _buffer_pool_usage_pct(status) == 64.2


def test_usage_pct_zero_total_guarded_to_none():
    status = {
        "Innodb_buffer_pool_pages_total": "0",
        "Innodb_buffer_pool_pages_free": "0",
    }
    assert _buffer_pool_usage_pct(status) is None


def test_usage_pct_none_when_counters_absent():
    assert _buffer_pool_usage_pct({}) is None


# ---------------------------------------------------------------------------
# _add_status_metrics / _add_variable_metrics
# ---------------------------------------------------------------------------


def test_add_status_metrics_full():
    metrics = {}
    _add_status_metrics(metrics, _parse_status(MYSQL8_STATUS))
    assert metrics["connections"] == 42
    assert metrics["queries"] == 1234567
    assert metrics["slow_queries"] == 12
    assert metrics["aborted_connects"] == 3
    assert metrics["uptime"] == 864000
    assert metrics["innodb_buffer_pool_hit_ratio"] == 99.87
    assert metrics["innodb_buffer_pool_usage_pct"] == 64.2


def test_add_status_metrics_omits_absent_keys():
    metrics = {}
    _add_status_metrics(metrics, {"Threads_connected": "5"})
    assert metrics == {"connections": 5}


def test_add_variable_metrics():
    metrics = {}
    _add_variable_metrics(metrics, _parse_status(MYSQL8_VARS))
    assert metrics == {"max_connections": 151, "version": "8.0.36"}


def test_add_variable_metrics_omits_absent():
    metrics = {}
    _add_variable_metrics(metrics, {})
    assert metrics == {}


# ---------------------------------------------------------------------------
# _build_replication: MySQL8 / MariaDB spellings + NULL lag
# ---------------------------------------------------------------------------


def test_build_replication_mysql8():
    repl = _build_replication(_parse_vertical(MYSQL8_REPLICA))
    assert repl == {
        "lag_seconds": 5,
        "io_running": True,
        "sql_running": True,
        "running": True,
    }


def test_build_replication_mariadb():
    repl = _build_replication(_parse_vertical(MARIADB_REPLICA))
    assert repl == {
        "lag_seconds": 0,
        "io_running": True,
        "sql_running": True,
        "running": True,
    }


def test_build_replication_null_lag_not_running():
    repl = _build_replication(_parse_vertical(REPLICA_NULL_LAG))
    assert repl["lag_seconds"] is None
    assert repl["running"] is False
    assert repl["io_running"] is True
    assert repl["sql_running"] is False


# ---------------------------------------------------------------------------
# _get_replication: REPLICA -> SLAVE fallback, degradation semantics
# ---------------------------------------------------------------------------


def test_get_replication_mysql8_replica():
    with patch(f"{MY}._run_mysql", return_value=(MYSQL8_REPLICA, None, "")):
        is_replica, repl = _get_replication("mysql", _conn())
    assert is_replica is True
    assert repl["lag_seconds"] == 5


def test_get_replication_falls_back_to_slave():
    calls = []

    def fake(binary, sql, conn, vertical=False):
        calls.append(sql)
        if "REPLICA STATUS" in sql:
            return None, "error", "You have an error in your SQL syntax"
        return MARIADB_REPLICA, None, ""

    with patch(f"{MY}._run_mysql", side_effect=fake):
        is_replica, repl = _get_replication("mysql", _conn())
    assert is_replica is True
    assert repl["lag_seconds"] == 0
    assert any("SLAVE STATUS" in s for s in calls)


def test_get_replication_not_a_replica():
    with patch(f"{MY}._run_mysql", return_value=("", None, "")):
        assert _get_replication("mysql", _conn()) == (False, None)


def test_get_replication_undetermined_when_both_fail():
    with patch(f"{MY}._run_mysql", return_value=(None, "auth_failed", "denied")):
        assert _get_replication("mysql", _conn()) == (None, None)


# ---------------------------------------------------------------------------
# _failure
# ---------------------------------------------------------------------------


def test_failure_includes_cleaned_detail():
    stderr = (
        "mysql: [Warning] Using a password on the command line interface "
        "can be insecure.\nERROR 2002: Can't connect\n"
    )
    result = _failure("connection_refused", stderr)
    assert result["reachable"] is False
    assert result["error"] == "connection_refused"
    assert result["error_detail"] == "ERROR 2002: Can't connect"


def test_failure_omits_empty_detail():
    assert _failure("timeout", "") == {"reachable": False, "error": "timeout"}


def test_failure_truncates_detail():
    result = _failure("error", "x" * 900)
    assert len(result["error_detail"]) == 500


# ---------------------------------------------------------------------------
# mysql_metrics: orchestration (end-to-end via mocked subprocess)
# ---------------------------------------------------------------------------


def test_metrics_none_when_client_absent():
    with patch(f"{MY}.shutil.which", return_value=None):
        assert mysql_metrics() is None


def test_metrics_none_when_binary_vanishes_at_probe():
    """which() finds it but the exec raises FileNotFoundError -> unknown (None)."""
    with patch(f"{MY}.shutil.which", return_value="/usr/bin/mysql"), patch(
        f"{MY}.subprocess.run", side_effect=FileNotFoundError()
    ):
        assert mysql_metrics() is None


def test_metrics_mysql8_full_payload():
    result = run_metrics(
        {
            "GLOBAL STATUS": (MYSQL8_STATUS, "", 0),
            "VARIABLES": (MYSQL8_VARS, "", 0),
            "REPLICA STATUS": (MYSQL8_REPLICA, "", 0),
        },
        host="localhost",
        user="root",
        password="x",
    )
    assert result["reachable"] is True
    assert result["version"] == "8.0.36"
    assert result["connections"] == 42
    assert result["max_connections"] == 151
    assert result["queries"] == 1234567
    assert result["slow_queries"] == 12
    assert result["aborted_connects"] == 3
    assert result["uptime"] == 864000
    assert result["innodb_buffer_pool_hit_ratio"] == 99.87
    assert result["innodb_buffer_pool_usage_pct"] == 64.2
    assert result["is_replica"] is True
    assert result["replication"] == {
        "lag_seconds": 5,
        "io_running": True,
        "sql_running": True,
        "running": True,
    }


def test_metrics_mariadb_full_payload_via_slave_fallback():
    result = run_metrics(
        {
            "GLOBAL STATUS": (MARIADB_STATUS, "", 0),
            "VARIABLES": (MARIADB_VARS, "", 0),
            # MariaDB rejects SHOW REPLICA STATUS -> fall back to SHOW SLAVE STATUS.
            "REPLICA STATUS": ("", "You have an error in your SQL syntax", 1),
            "SLAVE STATUS": (MARIADB_REPLICA, "", 0),
        }
    )
    assert result["reachable"] is True
    assert result["version"] == "10.11.6-MariaDB"
    assert result["connections"] == 7
    assert result["max_connections"] == 100
    # read_requests == 0 div/0 guard, equal total/free -> 0.0 usage.
    assert result["innodb_buffer_pool_hit_ratio"] == 100.0
    assert result["innodb_buffer_pool_usage_pct"] == 0.0
    assert result["is_replica"] is True
    assert result["replication"]["lag_seconds"] == 0
    assert result["replication"]["running"] is True


def test_metrics_non_replica_omits_replication():
    result = run_metrics(
        {
            "GLOBAL STATUS": (MYSQL8_STATUS, "", 0),
            "VARIABLES": (MYSQL8_VARS, "", 0),
            "REPLICA STATUS": ("", "", 0),  # empty -> not a replica
        }
    )
    assert result["is_replica"] is False
    assert "replication" not in result


def test_metrics_null_lag_replica():
    result = run_metrics(
        {
            "GLOBAL STATUS": (MYSQL8_STATUS, "", 0),
            "VARIABLES": (MYSQL8_VARS, "", 0),
            "REPLICA STATUS": (REPLICA_NULL_LAG, "", 0),
        }
    )
    assert result["is_replica"] is True
    assert result["replication"]["lag_seconds"] is None
    assert result["replication"]["running"] is False


def test_metrics_variables_failure_stays_reachable():
    """A failing VARIABLES query drops version/max_connections, not reachable."""
    result = run_metrics(
        {
            "GLOBAL STATUS": (MYSQL8_STATUS, "", 0),
            "VARIABLES": ("", "ERROR 1227: Access denied", 1),
            "REPLICA STATUS": ("", "", 0),
        }
    )
    assert result["reachable"] is True
    assert "version" not in result
    assert "max_connections" not in result
    assert result["connections"] == 42


def test_metrics_replication_undetermined_omits_is_replica():
    """Both replica queries denied -> is_replica omitted, reachable stays True."""
    result = run_metrics(
        {
            "GLOBAL STATUS": (MYSQL8_STATUS, "", 0),
            "VARIABLES": (MYSQL8_VARS, "", 0),
            "REPLICA STATUS": ("", "ERROR 1227: Access denied", 1),
            "SLAVE STATUS": ("", "ERROR 1227: Access denied", 1),
        }
    )
    assert result["reachable"] is True
    assert "is_replica" not in result
    assert "replication" not in result


def test_metrics_auth_failure_is_config_error_payload():
    result = run_metrics(
        {
            "GLOBAL STATUS": (
                "",
                "ERROR 1045 (28000): Access denied for user 'root'@'localhost'",
                1,
            ),
        }
    )
    assert result["reachable"] is False
    assert result["error"] == "auth_failed"
    assert "Access denied" in result["error_detail"]


def test_metrics_connection_refused_payload():
    result = run_metrics(
        {
            "GLOBAL STATUS": (
                "",
                "ERROR 2002 (HY000): Can't connect to local MySQL server "
                "through socket '/run/mysqld/mysqld.sock' (2)",
                1,
            ),
        }
    )
    assert result["reachable"] is False
    assert result["error"] == "connection_refused"


def test_metrics_timeout_payload():
    with patch(f"{MY}.shutil.which", return_value="/usr/bin/mysql"), patch(
        f"{MY}.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="mysql", timeout=10),
    ):
        result = mysql_metrics()
    assert result == {"reachable": False, "error": "timeout"}


def test_metrics_tolerates_unknown_config_keys():
    """An unexpected backend config key is ignored, not a TypeError -> crash."""
    result = run_metrics(
        {
            "GLOBAL STATUS": (MYSQL8_STATUS, "", 0),
            "VARIABLES": (MYSQL8_VARS, "", 0),
            "REPLICA STATUS": ("", "", 0),
        },
        host="localhost",
        future_option="whatever",
    )
    assert result["reachable"] is True
