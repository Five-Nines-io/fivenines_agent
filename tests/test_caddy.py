"""Tests for the Caddy admin API collector.

Only requests.get is mocked: each case routes the three admin API endpoints
(/config/, /reverse_proxy/upstreams, /pki/ca/local) to canned responses and
the real collector builds the payload from them.
"""

import json
from unittest.mock import MagicMock, patch

import requests

from fivenines_agent.caddy import caddy_metrics

ADMIN = "http://localhost:2019"

CONFIG = {
    "apps": {
        "http": {
            "servers": {
                "srv0": {"listen": [":443"]},
                "srv1": {"listen": [":80"]},
            }
        },
        "tls": {"automation": {"policies": [{"subjects": ["example.com"]}]}},
    }
}

# Caddy's real /reverse_proxy/upstreams rows carry address, num_requests and
# fails only; the collector reads a missing "healthy" as healthy.
UPSTREAMS = [
    {"address": "10.0.0.1:8080", "num_requests": 4, "fails": 0},
    {"address": "10.0.0.2:8080", "num_requests": 1, "fails": 3, "healthy": False},
]

PKI = {
    "id": "local",
    "root_common_name": "Caddy Local Authority - 2026 ECC Root",
    "intermediate_common_name": "Caddy Local Authority - ECC Intermediate",
}


def _response(body=None, status=200, text=None):
    """A stand-in requests.Response. *body* is what .json() returns; *text*
    defaults to its JSON encoding (the collector checks .text before parsing)."""
    resp = MagicMock()
    resp.status_code = status
    resp.text = json.dumps(body) if text is None else text
    resp.json.return_value = body
    return resp


def _route(config=None, upstreams=None, pki=None):
    """requests.get side effect mapping each admin endpoint to a response (or
    an exception instance to raise)."""
    routes = {
        f"{ADMIN}/config/": config,
        f"{ADMIN}/reverse_proxy/upstreams": upstreams,
        f"{ADMIN}/pki/ca/local": pki,
    }

    def fake_get(url, timeout):
        assert timeout == 5
        outcome = routes[url]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return fake_get


def test_full_payload_from_all_three_endpoints():
    fake_get = _route(
        config=_response(CONFIG), upstreams=_response(UPSTREAMS), pki=_response(PKI)
    )
    with patch("fivenines_agent.caddy.requests.get", side_effect=fake_get) as get:
        out = caddy_metrics()

    assert out == {
        "config_loaded": True,
        "upstreams": [
            {
                "address": "10.0.0.1:8080",
                "num_requests": 4,
                "fails": 0,
                "healthy": True,
            },
            {
                "address": "10.0.0.2:8080",
                "num_requests": 1,
                "fails": 3,
                "healthy": False,
            },
        ],
        "upstreams_total": 2,
        "upstreams_healthy": 1,
        "upstreams_unhealthy": 1,
        "pki_enabled": True,
        "pki_root_cn": "Caddy Local Authority - 2026 ECC Root",
        "pki_intermediate_cn": "Caddy Local Authority - ECC Intermediate",
        "apps_configured": ["http", "tls"],
        "http_servers_count": 2,
        "tls_automation_policies": 1,
    }
    assert get.call_count == 3


def test_custom_admin_url_is_used_for_every_endpoint():
    base = "http://127.0.0.1:2020"
    seen = []

    def fake_get(url, timeout):
        seen.append(url)
        return _response({}, status=404)

    with patch("fivenines_agent.caddy.requests.get", side_effect=fake_get):
        assert caddy_metrics(admin_api_url=base) is None
    # A non-200 /config/ stops before the other two endpoints.
    assert seen == [f"{base}/config/"]


def test_non_200_config_returns_none():
    fake_get = _route(config=_response({}, status=403))
    with patch("fivenines_agent.caddy.requests.get", side_effect=fake_get) as get:
        assert caddy_metrics() is None
    get.assert_called_once()


def test_empty_config_body_has_no_app_counts():
    """An empty /config/ body is parsed as {} (no .json() call): the API is
    reachable, but there is nothing to count apps from. Upstreams and PKI
    answering non-200 leave no upstream keys and pki_enabled False."""
    config = _response(None, text="")
    fake_get = _route(
        config=config,
        upstreams=_response(None, status=404),
        pki=_response(None, status=404),
    )
    with patch("fivenines_agent.caddy.requests.get", side_effect=fake_get):
        out = caddy_metrics()

    assert out == {"config_loaded": True, "pki_enabled": False}
    config.json.assert_not_called()


def test_null_config_reads_as_not_loaded():
    """Caddy answers /config/ with JSON null when no config is loaded."""
    fake_get = _route(
        config=_response(None),
        upstreams=_response(None),
        pki=_response(None),
    )
    with patch("fivenines_agent.caddy.requests.get", side_effect=fake_get):
        out = caddy_metrics()

    # A null upstream list and a null PKI document fall back to empty values.
    assert out == {
        "config_loaded": False,
        "upstreams": [],
        "upstreams_total": 0,
        "upstreams_healthy": 0,
        "upstreams_unhealthy": 0,
        "pki_enabled": True,
        "pki_root_cn": "",
        "pki_intermediate_cn": "",
    }


def test_upstream_row_defaults_when_fields_are_missing():
    fake_get = _route(
        config=_response({}),
        upstreams=_response([{}]),
        pki=_response(None, status=404),
    )
    with patch("fivenines_agent.caddy.requests.get", side_effect=fake_get):
        out = caddy_metrics()

    assert out["upstreams"] == [
        {"address": "unknown", "num_requests": 0, "fails": 0, "healthy": True}
    ]
    assert out["upstreams_healthy"] == 1
    assert out["upstreams_unhealthy"] == 0


def test_upstreams_and_pki_failures_do_not_fail_the_collection():
    """No reverse proxy configured (or a transport error on the side
    endpoints) reports zero upstreams and PKI disabled, never None.

    This pins TODAY's behaviour, not the contract: a transport error is
    unknown, and shipping 0 upstreams_unhealthy for it reads as a false
    all-clear (#234). A fix that ships None there must change this test."""
    fake_get = _route(
        config=_response({"apps": {}}),
        upstreams=requests.exceptions.ConnectionError("reset"),
        pki=requests.exceptions.Timeout("slow"),
    )
    with patch("fivenines_agent.caddy.requests.get", side_effect=fake_get), patch(
        "fivenines_agent.caddy.log"
    ) as mock_log:
        out = caddy_metrics()

    assert out == {
        "config_loaded": True,
        "upstreams_total": 0,
        "upstreams_healthy": 0,
        "upstreams_unhealthy": 0,
        "pki_enabled": False,
        "apps_configured": [],
        "http_servers_count": 0,
        "tls_automation_policies": 0,
    }
    mock_log.assert_called_once()
    assert "Could not fetch Caddy upstreams" in mock_log.call_args.args[0]
    assert mock_log.call_args.args[1] == "debug"


def test_null_tls_policies_count_as_zero():
    config = {"apps": {"tls": {"automation": {"policies": None}}}}
    fake_get = _route(
        config=_response(config),
        upstreams=_response(None, status=404),
        pki=_response(None, status=404),
    )
    with patch("fivenines_agent.caddy.requests.get", side_effect=fake_get):
        out = caddy_metrics()

    assert out["apps_configured"] == ["tls"]
    assert out["http_servers_count"] == 0
    assert out["tls_automation_policies"] == 0


def test_connection_refused_returns_none_logged_at_debug():
    fake_get = _route(config=requests.exceptions.ConnectionError("refused"))
    with patch("fivenines_agent.caddy.requests.get", side_effect=fake_get), patch(
        "fivenines_agent.caddy.log"
    ) as mock_log:
        assert caddy_metrics() is None
    mock_log.assert_called_once_with("Cannot connect to Caddy admin API", "debug")


def test_unparseable_config_returns_none_logged_at_error():
    config = _response(None, text="<html>not json</html>")
    config.json.side_effect = ValueError("Expecting value")
    fake_get = _route(config=config)
    with patch("fivenines_agent.caddy.requests.get", side_effect=fake_get), patch(
        "fivenines_agent.caddy.log"
    ) as mock_log:
        assert caddy_metrics() is None
    message, level = mock_log.call_args.args
    assert level == "error"
    assert "Error collecting Caddy metrics: Expecting value" == message
