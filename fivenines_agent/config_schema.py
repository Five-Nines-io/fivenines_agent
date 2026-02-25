"""Config validation and sanitization for API response config.

Validates and sanitizes the configuration dictionary received from
the fivenines API before it is used by collectors, preventing
security vulnerabilities from a compromised API backend.
"""

import re
import urllib.parse

from fivenines_agent.debug import log


LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}

INTERVAL_MIN = 30
INTERVAL_MAX = 3600
TIMEOUT_MIN = 1
TIMEOUT_MAX = 60
RETRY_MIN = 1
RETRY_MAX = 10
RETRY_INTERVAL_MIN = 1
RETRY_INTERVAL_MAX = 120

ALLOWED_QEMU_URIS = {"qemu:///system", "qemu:///session"}


def _strip_crlf(value: str) -> str:
    return re.sub(r"[\r\n]", "", value)


def _is_loopback_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if hostname is None:
            return False
        return hostname.lower() in LOOPBACK_HOSTS
    except Exception:
        return False


def _is_loopback_host(host: str) -> bool:
    return str(host).lower() in LOOPBACK_HOSTS


def _clamp(value, lo: int, hi: int, default: int) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _validate_request_options(opts: dict) -> dict:
    return {
        "timeout": _clamp(opts.get("timeout", 5), TIMEOUT_MIN, TIMEOUT_MAX, 5),
        "retry": _clamp(opts.get("retry", 3), RETRY_MIN, RETRY_MAX, 3),
        "retry_interval": _clamp(
            opts.get("retry_interval", 5), RETRY_INTERVAL_MIN, RETRY_INTERVAL_MAX, 5
        ),
    }


def _sanitize_redis(cfg: dict):
    result = {}

    port = cfg.get("port", 6379)
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            log("config_schema: redis port out of range, disabling collector", "warn")
            return None
    except (TypeError, ValueError):
        log("config_schema: redis port invalid, disabling collector", "warn")
        return None
    result["port"] = port

    password = cfg.get("password")
    if password is not None:
        if not isinstance(password, str):
            log(
                "config_schema: redis password must be str, disabling collector",
                "warn",
            )
            return None
        password = _strip_crlf(password)
    result["password"] = password

    return result


def _sanitize_nginx(cfg: dict):
    result = {}
    url = cfg.get("status_page_url", "http://127.0.0.1:8080/nginx_status")
    if not _is_loopback_url(url):
        log(
            f"config_schema: nginx status_page_url {url!r} is not loopback,"
            " disabling collector",
            "warn",
        )
        return None
    result["status_page_url"] = url
    return result


def _sanitize_caddy(cfg: dict):
    result = {}
    url = cfg.get("admin_api_url", "http://localhost:2019")
    if not _is_loopback_url(url):
        log(
            f"config_schema: caddy admin_api_url {url!r} is not loopback,"
            " disabling collector",
            "warn",
        )
        return None
    result["admin_api_url"] = url
    return result


def _sanitize_postgresql(cfg: dict):
    result = {}

    host = cfg.get("host", "localhost")
    if not _is_loopback_host(host):
        log(
            f"config_schema: postgresql host {host!r} is not loopback,"
            " disabling collector",
            "warn",
        )
        return None
    result["host"] = host

    port = cfg.get("port", 5432)
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            log(
                "config_schema: postgresql port out of range, disabling collector",
                "warn",
            )
            return None
    except (TypeError, ValueError):
        log("config_schema: postgresql port invalid, disabling collector", "warn")
        return None
    result["port"] = port

    user = cfg.get("user", "postgres")
    if not isinstance(user, str):
        log(
            "config_schema: postgresql user must be str, disabling collector",
            "warn",
        )
        return None
    result["user"] = user

    database = cfg.get("database", "postgres")
    if not isinstance(database, str):
        log(
            "config_schema: postgresql database must be str, disabling collector",
            "warn",
        )
        return None
    result["database"] = database

    password = cfg.get("password")
    if password is not None:
        if not isinstance(password, str):
            log(
                "config_schema: postgresql password must be str or None,"
                " disabling collector",
                "warn",
            )
            return None
        password = _strip_crlf(password)
    result["password"] = password

    return result


def _sanitize_proxmox(cfg: dict):
    result = {}

    host = cfg.get("host", "localhost")
    if not _is_loopback_host(host):
        log(
            f"config_schema: proxmox host {host!r} is not loopback,"
            " disabling collector",
            "warn",
        )
        return None
    result["host"] = host

    port = cfg.get("port", 8006)
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            log(
                "config_schema: proxmox port out of range, disabling collector",
                "warn",
            )
            return None
    except (TypeError, ValueError):
        log("config_schema: proxmox port invalid, disabling collector", "warn")
        return None
    result["port"] = port

    token_id = cfg.get("token_id")
    if token_id is not None and not isinstance(token_id, str):
        log(
            "config_schema: proxmox token_id must be str or None,"
            " disabling collector",
            "warn",
        )
        return None
    result["token_id"] = token_id

    token_secret = cfg.get("token_secret")
    if token_secret is not None and not isinstance(token_secret, str):
        log(
            "config_schema: proxmox token_secret must be str or None,"
            " disabling collector",
            "warn",
        )
        return None
    result["token_secret"] = token_secret

    verify_ssl = cfg.get("verify_ssl", True)
    if verify_ssl is False:
        log("config_schema: proxmox verify_ssl=False rejected, forcing True", "warn")
    result["verify_ssl"] = True

    return result


def _sanitize_docker(cfg: dict):
    result = {}
    socket_url = cfg.get("socket_url")
    if socket_url is not None:
        if not isinstance(socket_url, str) or not socket_url.startswith("unix://"):
            log(
                f"config_schema: docker socket_url {socket_url!r} must be"
                " unix:// or None, disabling collector",
                "warn",
            )
            return None
    result["socket_url"] = socket_url
    return result


def _sanitize_qemu(cfg: dict):
    result = {}
    uri = cfg.get("uri")
    if uri is not None:
        if uri not in ALLOWED_QEMU_URIS:
            log(
                f"config_schema: qemu uri {uri!r} is not allowed,"
                " disabling collector",
                "warn",
            )
            return None
        result["uri"] = uri
    return result


def _sanitize_ports(cfg: dict):
    monitored_ports = cfg.get("monitored_ports", [])
    if not isinstance(monitored_ports, list):
        log(
            "config_schema: ports.monitored_ports must be a list,"
            " disabling collector",
            "warn",
        )
        return None
    valid_ports = []
    for p in monitored_ports:
        try:
            port = int(p)
            if 1 <= port <= 65535:
                valid_ports.append(port)
            else:
                log(
                    f"config_schema: monitored port {p!r} out of range, skipping",
                    "warn",
                )
        except (TypeError, ValueError):
            log(
                f"config_schema: invalid monitored port {p!r}, skipping",
                "warn",
            )
    return {"monitored_ports": valid_ports}


def _sanitize_ping(cfg):
    if not isinstance(cfg, dict):
        log("config_schema: ping config must be a dict, disabling", "warn")
        return None
    result = {}
    for k, v in cfg.items():
        if isinstance(k, str) and isinstance(v, str) and v:
            result[k] = v
        else:
            log(
                f"config_schema: ping entry {k!r} has invalid value {v!r}, skipping",
                "warn",
            )
    return result if result else None


def validate_config(raw: dict) -> dict:
    """Validate and sanitize API response config.

    Returns a clean config dict. Unknown keys are dropped.
    Security violations are logged and the offending section is dropped/overridden.
    """
    config = {}

    # Structural keys
    config["enabled"] = bool(raw.get("enabled", False))
    config["interval"] = _clamp(raw.get("interval", 60), INTERVAL_MIN, INTERVAL_MAX, 60)
    config["request_options"] = _validate_request_options(
        raw.get("request_options") or {}
    )

    # Boolean feature flags (no kwargs)
    for key in (
        "cpu",
        "memory",
        "network",
        "partitions",
        "io",
        "smart_storage_health",
        "raid_storage_health",
        "processes",
        "temperatures",
        "fans",
        "fail2ban",
        "ipv4",
        "ipv6",
    ):
        val = raw.get(key)
        config[key] = bool(val) if val is not None else None

    # pass_kwargs=True collectors -- validate and sanitize
    collector_sanitizers = {
        "redis": _sanitize_redis,
        "nginx": _sanitize_nginx,
        "caddy": _sanitize_caddy,
        "postgresql": _sanitize_postgresql,
        "proxmox": _sanitize_proxmox,
        "docker": _sanitize_docker,
        "qemu": _sanitize_qemu,
        "ports": _sanitize_ports,
    }
    for key, sanitizer in collector_sanitizers.items():
        raw_val = raw.get(key)
        if not raw_val:
            config[key] = raw_val  # None/False -- disabled, preserve as-is
        elif isinstance(raw_val, dict):
            config[key] = sanitizer(raw_val)  # may return None on security violation
        else:
            config[key] = raw_val  # True/other truthy scalar -- enable with no kwargs

    # ping: special dict-of-hosts structure
    config["ping"] = _sanitize_ping(raw.get("ping")) if raw.get("ping") else None

    # packages: passed through as-is to packages_sync() which handles its own structure
    config["packages"] = raw.get("packages")

    return config
