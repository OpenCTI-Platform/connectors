from unittest.mock import MagicMock

import requests
from visionheight_client.api_client import VisionHeightClient


def _make_client() -> VisionHeightClient:
    """Build a client with a real (trailing-slash) base URL and a mocked session."""
    client = VisionHeightClient(
        helper=MagicMock(), base_url="http://test.com/", api_key="test-key"
    )
    client.session = MagicMock()
    return client


def test_base_url_trailing_slash_is_stripped():
    client = _make_client()
    assert client.base_url == "http://test.com"


def test_get_ip_success_returns_json_and_builds_url():
    client = _make_client()
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"value": "1.2.3.4"}
    client.session.get.return_value = response

    result = client.get_ip("1.2.3.4")

    assert result == {"value": "1.2.3.4"}
    called_url = client.session.get.call_args[0][0]
    assert called_url == "http://test.com/ip/1.2.3.4"


def test_get_domain_success_returns_json_and_builds_url():
    client = _make_client()
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"value": "example.com"}
    client.session.get.return_value = response

    result = client.get_domain("example.com")

    assert result == {"value": "example.com"}
    assert client.session.get.call_args[0][0] == "http://test.com/domain/example.com"


def test_request_error_with_response_logs_status_code_and_truncated_body():
    client = _make_client()
    response = MagicMock()
    response.status_code = 500
    response.text = "x" * 1000
    client.session.get.side_effect = requests.exceptions.HTTPError(response=response)

    result = client.get_ip("1.2.3.4")

    assert result is None
    _, meta = client.helper.connector_logger.error.call_args[0]
    assert meta["status_code"] == 500
    assert meta["response_body"] == "x" * 500  # truncated to first 500 chars


def test_request_error_without_response_logs_none_fields():
    client = _make_client()
    client.session.get.side_effect = requests.exceptions.ConnectionError()

    result = client.get_domain("example.com")

    assert result is None
    _, meta = client.helper.connector_logger.error.call_args[0]
    assert meta["status_code"] is None
    assert meta["response_body"] is None
