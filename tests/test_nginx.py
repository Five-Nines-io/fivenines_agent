"""Tests for the NGINX stub_status collector.

Only requests.get is mocked; each case feeds a canned stub_status page back
through the real positional parse.
"""

from unittest.mock import MagicMock, patch

import requests
from requests.structures import CaseInsensitiveDict

from fivenines_agent.nginx import nginx_metrics

# Verbatim stub_status layout, trailing spaces included (nginx writes them).
STUB_STATUS = (
    "Active connections: 291 \n"
    "server accepts handled requests\n"
    " 16630948 16630948 31070465 \n"
    "Reading: 6 Writing: 179 Waiting: 106 \n"
)


def _response(text="", status=200, server="nginx/1.24.0"):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    headers = CaseInsensitiveDict()
    if server is not None:
        headers["Server"] = server
    resp.headers = headers
    return resp


def test_stub_status_is_parsed():
    with patch(
        "fivenines_agent.nginx.requests.get", return_value=_response(STUB_STATUS)
    ) as get:
        out = nginx_metrics()

    assert out == {
        "nginx_version": "nginx/1.24.0",
        "active_connections": 291,
        "reading_connections": 6,
        "writing_connections": 179,
        "waiting_connections": 106,
    }
    get.assert_called_once_with("http://127.0.0.1:8080/nginx_status", timeout=5)


def test_custom_status_url_is_fetched():
    url = "http://localhost/basic_status"
    with patch(
        "fivenines_agent.nginx.requests.get", return_value=_response(STUB_STATUS)
    ) as get:
        assert nginx_metrics(status_page_url=url)["active_connections"] == 291
    get.assert_called_once_with(url, timeout=5)


def test_non_200_returns_none():
    with patch(
        "fivenines_agent.nginx.requests.get",
        return_value=_response("Not Found", status=404),
    ):
        assert nginx_metrics() is None


def test_empty_body_reports_version_only():
    with patch("fivenines_agent.nginx.requests.get", return_value=_response("")):
        assert nginx_metrics() == {"nginx_version": "nginx/1.24.0"}


def test_truncated_page_returns_none_and_logs_error():
    """A page that is not stub_status (a proxy error page, a truncated
    body) fails the whole read rather than shipping partial counters."""
    with patch(
        "fivenines_agent.nginx.requests.get",
        return_value=_response("Active connections: 3 \n"),
    ), patch("fivenines_agent.nginx.log") as mock_log:
        assert nginx_metrics() is None
    message, level = mock_log.call_args.args
    assert level == "error"
    assert message.startswith("Error collecting NGINX metrics:")


def test_missing_server_header_returns_none():
    """The version comes from the Server header, read with [] -- a response
    without one (stripped by a proxy) fails the collection."""
    with patch(
        "fivenines_agent.nginx.requests.get",
        return_value=_response(STUB_STATUS, server=None),
    ), patch("fivenines_agent.nginx.log") as mock_log:
        assert nginx_metrics() is None
    assert mock_log.call_args.args[1] == "error"


def test_connection_error_returns_none_and_logs_error():
    with patch(
        "fivenines_agent.nginx.requests.get",
        side_effect=requests.exceptions.ConnectionError("refused"),
    ), patch("fivenines_agent.nginx.log") as mock_log:
        assert nginx_metrics() is None
    mock_log.assert_called_once_with("Error collecting NGINX metrics: refused", "error")
