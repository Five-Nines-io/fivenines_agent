"""Tests for config_schema validation module (100% coverage required)."""

from unittest.mock import patch

from fivenines_agent.config_schema import (
    INTERVAL_MAX,
    INTERVAL_MIN,
    RETRY_INTERVAL_MAX,
    RETRY_INTERVAL_MIN,
    RETRY_MAX,
    RETRY_MIN,
    TIMEOUT_MAX,
    TIMEOUT_MIN,
    _clamp,
    _is_loopback_host,
    _is_loopback_url,
    _sanitize_caddy,
    _sanitize_docker,
    _sanitize_nginx,
    _sanitize_ping,
    _sanitize_ports,
    _sanitize_postgresql,
    _sanitize_proxmox,
    _sanitize_qemu,
    _sanitize_redis,
    _strip_crlf,
    _validate_request_options,
    validate_config,
)


# ---------------------------------------------------------------------------
# _strip_crlf
# ---------------------------------------------------------------------------


def test_strip_crlf_removes_cr_and_lf():
    assert _strip_crlf("pass\r\nFLUSHALL") == "passFLUSHALL"


def test_strip_crlf_no_op_for_clean_string():
    assert _strip_crlf("normal_password") == "normal_password"


def test_strip_crlf_removes_standalone_cr():
    assert _strip_crlf("a\rb") == "ab"


# ---------------------------------------------------------------------------
# _is_loopback_url
# ---------------------------------------------------------------------------


def test_is_loopback_url_127():
    assert _is_loopback_url("http://127.0.0.1:8080/path") is True


def test_is_loopback_url_localhost():
    assert _is_loopback_url("http://localhost:2019") is True


def test_is_loopback_url_ipv6_loopback():
    assert _is_loopback_url("http://[::1]:9090/") is True


def test_is_loopback_url_external():
    assert _is_loopback_url("http://external.example.com/path") is False


def test_is_loopback_url_no_hostname():
    # urlparse of a plain path returns no hostname
    assert _is_loopback_url("not-a-url") is False


def test_is_loopback_url_exception_returns_false():
    with patch("urllib.parse.urlparse", side_effect=ValueError("bad url")):
        assert _is_loopback_url("http://anything") is False


def test_is_loopback_url_cloud_metadata():
    assert _is_loopback_url("http://169.254.169.254/latest") is False


# ---------------------------------------------------------------------------
# _is_loopback_host
# ---------------------------------------------------------------------------


def test_is_loopback_host_localhost():
    assert _is_loopback_host("localhost") is True


def test_is_loopback_host_case_insensitive():
    assert _is_loopback_host("LOCALHOST") is True


def test_is_loopback_host_127():
    assert _is_loopback_host("127.0.0.1") is True


def test_is_loopback_host_ipv6():
    assert _is_loopback_host("::1") is True


def test_is_loopback_host_external():
    assert _is_loopback_host("192.168.1.100") is False


def test_is_loopback_host_converts_to_str():
    # Should not raise even if passed a non-string
    assert _is_loopback_host(127001) is False


# ---------------------------------------------------------------------------
# _clamp
# ---------------------------------------------------------------------------


def test_clamp_in_range():
    assert _clamp(30, INTERVAL_MIN, INTERVAL_MAX, 60) == 30


def test_clamp_below_min():
    assert _clamp(2, INTERVAL_MIN, INTERVAL_MAX, 60) == INTERVAL_MIN


def test_clamp_above_max():
    assert _clamp(9999, INTERVAL_MIN, INTERVAL_MAX, 60) == INTERVAL_MAX


def test_clamp_invalid_string():
    assert _clamp("bad", INTERVAL_MIN, INTERVAL_MAX, 60) == 60


def test_clamp_none():
    assert _clamp(None, INTERVAL_MIN, INTERVAL_MAX, 60) == 60


def test_clamp_at_exact_min():
    assert _clamp(INTERVAL_MIN, INTERVAL_MIN, INTERVAL_MAX, 60) == INTERVAL_MIN


def test_clamp_at_exact_max():
    assert _clamp(INTERVAL_MAX, INTERVAL_MIN, INTERVAL_MAX, 60) == INTERVAL_MAX


def test_clamp_numeric_string():
    assert _clamp("60", INTERVAL_MIN, INTERVAL_MAX, 30) == 60


# ---------------------------------------------------------------------------
# _validate_request_options
# ---------------------------------------------------------------------------


def test_validate_request_options_empty_uses_defaults():
    result = _validate_request_options({})
    assert result == {"timeout": 5, "retry": 3, "retry_interval": 5}


def test_validate_request_options_valid_values():
    result = _validate_request_options({"timeout": 30, "retry": 5, "retry_interval": 10})
    assert result["timeout"] == 30
    assert result["retry"] == 5
    assert result["retry_interval"] == 10


def test_validate_request_options_clamps_timeout():
    result = _validate_request_options({"timeout": 999})
    assert result["timeout"] == TIMEOUT_MAX


def test_validate_request_options_clamps_retry():
    result = _validate_request_options({"retry": 0})
    assert result["retry"] == RETRY_MIN


def test_validate_request_options_clamps_retry_interval():
    result = _validate_request_options({"retry_interval": 999})
    assert result["retry_interval"] == RETRY_INTERVAL_MAX


def test_validate_request_options_invalid_type_uses_default():
    result = _validate_request_options({"timeout": "bad"})
    assert result["timeout"] == 5


# ---------------------------------------------------------------------------
# _sanitize_redis
# ---------------------------------------------------------------------------


def test_sanitize_redis_valid():
    result = _sanitize_redis({"port": 6379})
    assert result == {"port": 6379, "password": None}


def test_sanitize_redis_default_port():
    result = _sanitize_redis({})
    assert result == {"port": 6379, "password": None}


def test_sanitize_redis_with_password():
    result = _sanitize_redis({"port": 6379, "password": "secret"})
    assert result == {"port": 6379, "password": "secret"}


def test_sanitize_redis_crlf_password_stripped():
    result = _sanitize_redis({"port": 6379, "password": "pass\r\nFLUSHALL"})
    assert result == {"port": 6379, "password": "passFLUSHALL"}


def test_sanitize_redis_invalid_port_string():
    assert _sanitize_redis({"port": "bad"}) is None


def test_sanitize_redis_port_zero():
    assert _sanitize_redis({"port": 0}) is None


def test_sanitize_redis_port_too_high():
    assert _sanitize_redis({"port": 65536}) is None


def test_sanitize_redis_password_not_string():
    assert _sanitize_redis({"port": 6379, "password": 12345}) is None


def test_sanitize_redis_extra_keys_dropped():
    result = _sanitize_redis({"port": 6379, "unknown": "value"})
    assert result is not None
    assert "unknown" not in result


# ---------------------------------------------------------------------------
# _sanitize_nginx
# ---------------------------------------------------------------------------


def test_sanitize_nginx_default_url():
    result = _sanitize_nginx({})
    assert result == {"status_page_url": "http://127.0.0.1:8080/nginx_status"}


def test_sanitize_nginx_loopback_url():
    result = _sanitize_nginx({"status_page_url": "http://127.0.0.1:8080/nginx_status"})
    assert result == {"status_page_url": "http://127.0.0.1:8080/nginx_status"}


def test_sanitize_nginx_localhost_url():
    result = _sanitize_nginx({"status_page_url": "http://localhost:9090/nginx_status"})
    assert result is not None
    assert result["status_page_url"] == "http://localhost:9090/nginx_status"


def test_sanitize_nginx_external_url():
    assert _sanitize_nginx({"status_page_url": "http://external.com/nginx_status"}) is None


def test_sanitize_nginx_cloud_metadata_rejected():
    assert _sanitize_nginx({"status_page_url": "http://169.254.169.254/nginx"}) is None


# ---------------------------------------------------------------------------
# _sanitize_caddy
# ---------------------------------------------------------------------------


def test_sanitize_caddy_default_url():
    result = _sanitize_caddy({})
    assert result == {"admin_api_url": "http://localhost:2019"}


def test_sanitize_caddy_loopback_url():
    result = _sanitize_caddy({"admin_api_url": "http://localhost:2019"})
    assert result == {"admin_api_url": "http://localhost:2019"}


def test_sanitize_caddy_127_url():
    result = _sanitize_caddy({"admin_api_url": "http://127.0.0.1:2019"})
    assert result is not None


def test_sanitize_caddy_external_rejected():
    assert _sanitize_caddy({"admin_api_url": "http://attacker.example.com/admin"}) is None


# ---------------------------------------------------------------------------
# _sanitize_postgresql
# ---------------------------------------------------------------------------


def test_sanitize_postgresql_valid():
    result = _sanitize_postgresql(
        {"host": "localhost", "port": 5432, "user": "postgres", "database": "postgres"}
    )
    assert result == {
        "host": "localhost",
        "port": 5432,
        "user": "postgres",
        "database": "postgres",
        "password": None,
    }


def test_sanitize_postgresql_defaults():
    result = _sanitize_postgresql({})
    assert result is not None
    assert result["host"] == "localhost"
    assert result["port"] == 5432
    assert result["user"] == "postgres"
    assert result["database"] == "postgres"
    assert result["password"] is None


def test_sanitize_postgresql_remote_host_rejected():
    assert _sanitize_postgresql({"host": "192.168.1.100"}) is None


def test_sanitize_postgresql_invalid_port():
    assert _sanitize_postgresql({"host": "localhost", "port": "bad"}) is None


def test_sanitize_postgresql_port_out_of_range():
    assert _sanitize_postgresql({"host": "localhost", "port": 0}) is None


def test_sanitize_postgresql_crlf_password_stripped():
    result = _sanitize_postgresql({"host": "localhost", "password": "pass\r\nINJECT"})
    assert result is not None
    assert result["password"] == "passINJECT"


def test_sanitize_postgresql_password_not_string():
    assert _sanitize_postgresql({"host": "localhost", "password": 12345}) is None


def test_sanitize_postgresql_user_not_string():
    assert _sanitize_postgresql({"host": "localhost", "user": 99}) is None


def test_sanitize_postgresql_database_not_string():
    assert _sanitize_postgresql({"host": "localhost", "database": 99}) is None


def test_sanitize_postgresql_extra_keys_dropped():
    result = _sanitize_postgresql({"host": "localhost", "secret_key": "bad"})
    assert result is not None
    assert "secret_key" not in result


# ---------------------------------------------------------------------------
# _sanitize_proxmox
# ---------------------------------------------------------------------------


def test_sanitize_proxmox_valid():
    result = _sanitize_proxmox(
        {"host": "localhost", "token_id": "user@pam!tok", "token_secret": "s"}
    )
    assert result == {
        "host": "localhost",
        "port": 8006,
        "token_id": "user@pam!tok",
        "token_secret": "s",
        "verify_ssl": True,
    }


def test_sanitize_proxmox_defaults():
    result = _sanitize_proxmox({})
    assert result is not None
    assert result["host"] == "localhost"
    assert result["port"] == 8006
    assert result["token_id"] is None
    assert result["token_secret"] is None
    assert result["verify_ssl"] is True


def test_sanitize_proxmox_verify_ssl_false_allowed():
    result = _sanitize_proxmox({"host": "localhost", "verify_ssl": False})
    assert result is not None
    assert result["verify_ssl"] is False


def test_sanitize_proxmox_verify_ssl_true():
    result = _sanitize_proxmox({"host": "localhost", "verify_ssl": True})
    assert result is not None
    assert result["verify_ssl"] is True


def test_sanitize_proxmox_remote_host_rejected():
    assert _sanitize_proxmox({"host": "remote.proxmox.com"}) is None


def test_sanitize_proxmox_invalid_port():
    assert _sanitize_proxmox({"host": "localhost", "port": "bad"}) is None


def test_sanitize_proxmox_port_out_of_range():
    assert _sanitize_proxmox({"host": "localhost", "port": 70000}) is None


def test_sanitize_proxmox_token_id_not_string():
    assert _sanitize_proxmox({"host": "localhost", "token_id": 123}) is None


def test_sanitize_proxmox_token_secret_not_string():
    assert _sanitize_proxmox({"host": "localhost", "token_secret": 123}) is None


# ---------------------------------------------------------------------------
# _sanitize_docker
# ---------------------------------------------------------------------------


def test_sanitize_docker_none_socket():
    result = _sanitize_docker({})
    assert result == {"socket_url": None}


def test_sanitize_docker_unix_socket():
    result = _sanitize_docker({"socket_url": "unix:///var/run/docker.sock"})
    assert result == {"socket_url": "unix:///var/run/docker.sock"}


def test_sanitize_docker_tcp_rejected():
    assert _sanitize_docker({"socket_url": "tcp://external:2375"}) is None


def test_sanitize_docker_non_string_socket():
    assert _sanitize_docker({"socket_url": 12345}) is None


def test_sanitize_docker_http_rejected():
    assert _sanitize_docker({"socket_url": "http://localhost:2375"}) is None


def test_sanitize_docker_extra_keys_dropped():
    result = _sanitize_docker({"socket_url": None, "extra": "value"})
    assert result is not None
    assert "extra" not in result


# ---------------------------------------------------------------------------
# _sanitize_qemu
# ---------------------------------------------------------------------------


def test_sanitize_qemu_system():
    result = _sanitize_qemu({"uri": "qemu:///system"})
    assert result == {"uri": "qemu:///system"}


def test_sanitize_qemu_session():
    result = _sanitize_qemu({"uri": "qemu:///session"})
    assert result == {"uri": "qemu:///session"}


def test_sanitize_qemu_remote_uri_rejected():
    assert _sanitize_qemu({"uri": "qemu+ssh://user@remote/system"}) is None


def test_sanitize_qemu_no_uri_returns_empty():
    result = _sanitize_qemu({})
    assert result == {}


def test_sanitize_qemu_extra_keys_dropped():
    # Extra keys in cfg are not preserved (whitelist approach)
    result = _sanitize_qemu({"uri": "qemu:///system", "extra": "dropped"})
    assert result is not None
    assert "extra" not in result


# ---------------------------------------------------------------------------
# _sanitize_ports
# ---------------------------------------------------------------------------


def test_sanitize_ports_valid_list():
    result = _sanitize_ports({"monitored_ports": [80, 443, 8080]})
    assert result == {"monitored_ports": [80, 443, 8080]}


def test_sanitize_ports_empty_list():
    result = _sanitize_ports({"monitored_ports": []})
    assert result == {"monitored_ports": []}


def test_sanitize_ports_default_empty():
    result = _sanitize_ports({})
    assert result == {"monitored_ports": []}


def test_sanitize_ports_not_list():
    assert _sanitize_ports({"monitored_ports": "80,443"}) is None


def test_sanitize_ports_invalid_port_dropped():
    result = _sanitize_ports({"monitored_ports": [80, "bad", 443]})
    assert result is not None
    assert result["monitored_ports"] == [80, 443]


def test_sanitize_ports_out_of_range_dropped():
    result = _sanitize_ports({"monitored_ports": [80, 0, 65537, 443]})
    assert result is not None
    assert result["monitored_ports"] == [80, 443]


def test_sanitize_ports_extra_keys_dropped():
    result = _sanitize_ports({"monitored_ports": [80], "extra": "value"})
    assert result is not None
    assert "extra" not in result


# ---------------------------------------------------------------------------
# _sanitize_ping
# ---------------------------------------------------------------------------


def test_sanitize_ping_valid():
    result = _sanitize_ping({"google": "8.8.8.8:53", "cf": "1.1.1.1:53"})
    assert result == {"google": "8.8.8.8:53", "cf": "1.1.1.1:53"}


def test_sanitize_ping_not_dict():
    assert _sanitize_ping("not-a-dict") is None


def test_sanitize_ping_empty_value_dropped():
    assert _sanitize_ping({"host": ""}) is None


def test_sanitize_ping_non_string_value_dropped():
    assert _sanitize_ping({"host": 12345}) is None


def test_sanitize_ping_mixed_drops_invalid():
    result = _sanitize_ping({"good": "8.8.8.8:53", "bad": 123})
    assert result == {"good": "8.8.8.8:53"}


def test_sanitize_ping_all_invalid_returns_none():
    assert _sanitize_ping({"a": 1, "b": 2}) is None


# ---------------------------------------------------------------------------
# validate_config -- structural keys
# ---------------------------------------------------------------------------


def test_validate_config_empty_raw():
    result = validate_config({})
    assert result["enabled"] is False
    assert result["interval"] == 60
    assert result["request_options"] == {"timeout": 5, "retry": 3, "retry_interval": 5}


def test_validate_config_enabled_true():
    result = validate_config({"enabled": True})
    assert result["enabled"] is True


def test_validate_config_interval_clamped_low():
    result = validate_config({"interval": 1})
    assert result["interval"] == INTERVAL_MIN


def test_validate_config_interval_clamped_high():
    result = validate_config({"interval": 99999})
    assert result["interval"] == INTERVAL_MAX


def test_validate_config_interval_in_range():
    result = validate_config({"interval": 30})
    assert result["interval"] == 30


def test_validate_config_request_options_passthrough():
    result = validate_config({"request_options": {"timeout": 30, "retry": 5}})
    assert result["request_options"]["timeout"] == 30
    assert result["request_options"]["retry"] == 5


def test_validate_config_request_options_none_uses_defaults():
    result = validate_config({"request_options": None})
    assert result["request_options"] == {"timeout": 5, "retry": 3, "retry_interval": 5}


# ---------------------------------------------------------------------------
# validate_config -- boolean feature flags
# ---------------------------------------------------------------------------


def test_validate_config_flag_true():
    result = validate_config({"cpu": True})
    assert result["cpu"] is True


def test_validate_config_flag_false():
    # Explicitly False -- not None, but bool(False)
    result = validate_config({"cpu": False})
    assert result["cpu"] is False


def test_validate_config_flag_absent_is_none():
    result = validate_config({})
    assert result["cpu"] is None
    assert result["memory"] is None
    assert result["network"] is None


def test_validate_config_all_boolean_flags_present():
    flags = {
        "cpu": True,
        "memory": True,
        "network": False,
        "partitions": True,
        "io": True,
        "swap": True,
        "smart_storage_health": False,
        "raid_storage_health": False,
        "processes": True,
        "temperatures": True,
        "fans": True,
        "fail2ban": True,
        "ipv4": True,
        "ipv6": False,
        "nvidia_gpu": True,
    }
    result = validate_config(flags)
    for key, expected in flags.items():
        assert result[key] == expected, f"{key} mismatch"


# ---------------------------------------------------------------------------
# validate_config -- collector dispatch branches
# ---------------------------------------------------------------------------


def test_validate_config_collector_disabled_none():
    result = validate_config({"redis": None})
    assert result["redis"] is None


def test_validate_config_collector_disabled_false():
    result = validate_config({"redis": False})
    assert result["redis"] is False


def test_validate_config_collector_dict_valid():
    result = validate_config({"redis": {"port": 6379}})
    assert result["redis"] is not None
    assert result["redis"]["port"] == 6379


def test_validate_config_collector_dict_security_violation():
    # Invalid redis port -> sanitizer returns None -> collector disabled
    result = validate_config({"redis": {"port": 0}})
    assert result["redis"] is None


def test_validate_config_collector_truthy_scalar():
    # True (not a dict) -> passed through unchanged
    result = validate_config({"redis": True})
    assert result["redis"] is True


# ---------------------------------------------------------------------------
# validate_config -- ping
# ---------------------------------------------------------------------------


def test_validate_config_ping_present():
    result = validate_config({"ping": {"cf": "1.1.1.1:53"}})
    assert result["ping"] == {"cf": "1.1.1.1:53"}


def test_validate_config_ping_absent():
    result = validate_config({})
    assert result["ping"] is None


def test_validate_config_ping_falsy():
    result = validate_config({"ping": {}})
    assert result["ping"] is None


# ---------------------------------------------------------------------------
# validate_config -- packages
# ---------------------------------------------------------------------------


def test_validate_config_packages_passthrough():
    result = validate_config({"packages": {"scan": True, "hash": "abc123"}})
    assert result["packages"] == {"scan": True, "hash": "abc123"}


def test_validate_config_packages_absent():
    result = validate_config({})
    assert result["packages"] is None


# ---------------------------------------------------------------------------
# validate_config -- unknown keys are dropped
# ---------------------------------------------------------------------------


def test_validate_config_unknown_keys_dropped():
    result = validate_config({"unknown_key": "value", "another": 42, "enabled": True})
    assert "unknown_key" not in result
    assert "another" not in result
    assert result["enabled"] is True


# ---------------------------------------------------------------------------
# validate_config -- security constraint tests
# ---------------------------------------------------------------------------


def test_validate_config_proxmox_verify_ssl_passthrough():
    result = validate_config({"proxmox": {"host": "localhost", "verify_ssl": False}})
    assert result["proxmox"] is not None
    assert result["proxmox"]["verify_ssl"] is False


def test_validate_config_nginx_external_url_disabled():
    result = validate_config(
        {"nginx": {"status_page_url": "http://169.254.169.254/nginx"}}
    )
    assert result["nginx"] is None


def test_validate_config_postgresql_remote_host_disabled():
    result = validate_config({"postgresql": {"host": "attacker.example.com"}})
    assert result["postgresql"] is None


def test_validate_config_docker_tcp_disabled():
    result = validate_config({"docker": {"socket_url": "tcp://attacker:2375"}})
    assert result["docker"] is None


def test_validate_config_qemu_remote_uri_disabled():
    result = validate_config({"qemu": {"uri": "qemu+tcp://attacker/system"}})
    assert result["qemu"] is None


def test_validate_config_redis_crlf_injection_sanitized():
    result = validate_config({"redis": {"port": 6379, "password": "x\r\nFLUSHALL\r\n"}})
    assert result["redis"] is not None
    assert "\r" not in result["redis"]["password"]
    assert "\n" not in result["redis"]["password"]
