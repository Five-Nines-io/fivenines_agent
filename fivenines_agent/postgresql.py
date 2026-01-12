import subprocess
import json

from fivenines_agent.debug import debug, log


# PostgreSQL metrics collector
# Collects statistics from PostgreSQL using psql command
#
# Metrics collected:
# - Connection counts by state (active, idle, idle in transaction)
# - Database statistics (transactions, cache hit ratio)
# - Database sizes
# - Replication lag (if applicable)

def _run_psql_query(query, host='localhost', port=5432, user='postgres', password=None, database='postgres'):
    """Run a psql query and return JSON results."""
    env = {}
    if password:
        env['PGPASSWORD'] = password

    cmd = [
        'psql',
        '-h', str(host),
        '-p', str(port),
        '-U', str(user),
        '-d', str(database),
        '-t',  # Tuples only (no headers)
        '-A',  # Unaligned output
        '-c', query
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            env={**dict(__import__('os').environ), **env} if env else None
        )
        if result.returncode != 0:
            log(f"psql error: {result.stderr}", 'debug')
            return None
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        log("psql query timed out", 'debug')
        return None
    except FileNotFoundError:
        log("psql command not found", 'debug')
        return None
    except Exception as e:
        log(f"Error running psql: {e}", 'debug')
        return None


def _get_version(host, port, user, password, database):
    """Get PostgreSQL version."""
    result = _run_psql_query("SHOW server_version;", host, port, user, password, database)
    if result:
        return result.split()[0]  # Get just the version number
    return None


def _get_connection_stats(host, port, user, password, database):
    """Get connection statistics by state."""
    query = """
    SELECT state, count(*)
    FROM pg_stat_activity
    WHERE state IS NOT NULL
    GROUP BY state;
    """
    result = _run_psql_query(query, host, port, user, password, database)
    if not result:
        return {}

    stats = {
        'active': 0,
        'idle': 0,
        'idle_in_transaction': 0,
        'idle_in_transaction_aborted': 0,
        'fastpath_function_call': 0,
        'disabled': 0
    }

    for line in result.split('\n'):
        if '|' in line:
            parts = line.split('|')
            if len(parts) >= 2:
                state = parts[0].strip().replace(' ', '_')
                count = int(parts[1].strip())
                if state in stats:
                    stats[state] = count

    # Calculate total
    stats['total'] = sum(stats.values())
    return stats


def _get_database_stats(host, port, user, password, database):
    """Get database-level statistics."""
    query = """
    SELECT
        datname,
        numbackends,
        xact_commit,
        xact_rollback,
        blks_read,
        blks_hit,
        tup_returned,
        tup_fetched,
        tup_inserted,
        tup_updated,
        tup_deleted,
        conflicts,
        deadlocks
    FROM pg_stat_database
    WHERE datname NOT LIKE 'template%'
    ORDER BY datname;
    """
    result = _run_psql_query(query, host, port, user, password, database)
    if not result:
        return []

    databases = []
    for line in result.split('\n'):
        if '|' in line:
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 13 and parts[0]:
                blks_read = int(parts[4]) if parts[4] else 0
                blks_hit = int(parts[5]) if parts[5] else 0
                total_blks = blks_read + blks_hit

                databases.append({
                    'name': parts[0],
                    'connections': int(parts[1]) if parts[1] else 0,
                    'xact_commit': int(parts[2]) if parts[2] else 0,
                    'xact_rollback': int(parts[3]) if parts[3] else 0,
                    'blks_read': blks_read,
                    'blks_hit': blks_hit,
                    'cache_hit_ratio': round((blks_hit / total_blks * 100), 2) if total_blks > 0 else 100.0,
                    'tup_returned': int(parts[6]) if parts[6] else 0,
                    'tup_fetched': int(parts[7]) if parts[7] else 0,
                    'tup_inserted': int(parts[8]) if parts[8] else 0,
                    'tup_updated': int(parts[9]) if parts[9] else 0,
                    'tup_deleted': int(parts[10]) if parts[10] else 0,
                    'conflicts': int(parts[11]) if parts[11] else 0,
                    'deadlocks': int(parts[12]) if parts[12] else 0
                })

    return databases


def _get_database_sizes(host, port, user, password, database):
    """Get database sizes in bytes."""
    query = """
    SELECT datname, pg_database_size(datname) as size
    FROM pg_database
    WHERE datname NOT LIKE 'template%'
    ORDER BY datname;
    """
    result = _run_psql_query(query, host, port, user, password, database)
    if not result:
        return {}

    sizes = {}
    for line in result.split('\n'):
        if '|' in line:
            parts = line.split('|')
            if len(parts) >= 2 and parts[0].strip():
                sizes[parts[0].strip()] = int(parts[1].strip())

    return sizes


def _get_replication_lag(host, port, user, password, database):
    """Get replication lag in bytes (for replicas)."""
    # Check if this is a replica
    query = "SELECT pg_is_in_recovery();"
    result = _run_psql_query(query, host, port, user, password, database)

    if result and result.strip() == 't':
        # This is a replica, get lag
        lag_query = """
        SELECT
            CASE
                WHEN pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn() THEN 0
                ELSE EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp())
            END AS lag_seconds;
        """
        lag_result = _run_psql_query(lag_query, host, port, user, password, database)
        if lag_result and lag_result.strip():
            try:
                return float(lag_result.strip())
            except ValueError:
                return None
    return None


def _get_locks_count(host, port, user, password, database):
    """Get count of locks by mode."""
    query = """
    SELECT mode, count(*)
    FROM pg_locks
    GROUP BY mode;
    """
    result = _run_psql_query(query, host, port, user, password, database)
    if not result:
        return {}

    locks = {}
    for line in result.split('\n'):
        if '|' in line:
            parts = line.split('|')
            if len(parts) >= 2:
                mode = parts[0].strip()
                count = int(parts[1].strip())
                locks[mode] = count

    locks['total'] = sum(locks.values())
    return locks


@debug('postgresql_metrics')
def postgresql_metrics(host='localhost', port=5432, user='postgres', password=None, database='postgres'):
    """
    Collect metrics from PostgreSQL.

    Args:
        host: PostgreSQL host (default: localhost)
        port: PostgreSQL port (default: 5432)
        user: PostgreSQL user (default: postgres)
        password: PostgreSQL password (default: None, uses peer auth)
        database: Database to connect to (default: postgres)

    Returns:
        dict: Metrics dictionary or None on error
    """
    try:
        metrics = {}

        # Get version
        version = _get_version(host, port, user, password, database)
        if version is None:
            log("Cannot connect to PostgreSQL", 'debug')
            return None

        metrics['version'] = version

        # Get connection stats
        conn_stats = _get_connection_stats(host, port, user, password, database)
        if conn_stats:
            metrics['connections'] = conn_stats

        # Get database stats
        db_stats = _get_database_stats(host, port, user, password, database)
        if db_stats:
            metrics['databases'] = db_stats

            # Calculate totals across all databases
            metrics['total_xact_commit'] = sum(d['xact_commit'] for d in db_stats)
            metrics['total_xact_rollback'] = sum(d['xact_rollback'] for d in db_stats)
            metrics['total_deadlocks'] = sum(d['deadlocks'] for d in db_stats)

            # Calculate overall cache hit ratio
            total_hit = sum(d['blks_hit'] for d in db_stats)
            total_read = sum(d['blks_read'] for d in db_stats)
            total_blks = total_hit + total_read
            metrics['cache_hit_ratio'] = round((total_hit / total_blks * 100), 2) if total_blks > 0 else 100.0

        # Get database sizes
        sizes = _get_database_sizes(host, port, user, password, database)
        if sizes:
            metrics['database_sizes'] = sizes
            metrics['total_size'] = sum(sizes.values())

        # Get replication lag (if replica)
        replication_lag = _get_replication_lag(host, port, user, password, database)
        if replication_lag is not None:
            metrics['replication_lag_seconds'] = replication_lag
            metrics['is_replica'] = True
        else:
            metrics['is_replica'] = False

        # Get locks
        locks = _get_locks_count(host, port, user, password, database)
        if locks:
            metrics['locks'] = locks

        return metrics

    except Exception as e:
        log(f"Error collecting PostgreSQL metrics: {e}", 'error')
        return None
