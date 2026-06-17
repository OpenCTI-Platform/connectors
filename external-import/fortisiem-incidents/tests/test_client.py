from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests
from fortisiem_client import FortiSIEMClient, FortiSIEMClientError


def _make_client() -> FortiSIEMClient:
    fortisiem = SimpleNamespace(
        api_base_url="https://fortisiem.example.com",
        organization="super",
        username="api-user",
        password=SimpleNamespace(get_secret_value=lambda: "pw"),
        ssl_verify=True,
    )
    client = FortiSIEMClient(
        SimpleNamespace(fortisiem_incidents=fortisiem), MagicMock()
    )
    client.session = MagicMock()
    return client


def _response(payload, status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


def test_organization_prefix_in_auth():
    fortisiem = SimpleNamespace(
        api_base_url="https://fortisiem.example.com",
        organization="super",
        username="api-user",
        password=SimpleNamespace(get_secret_value=lambda: "pw"),
        ssl_verify=True,
    )
    client = FortiSIEMClient(
        SimpleNamespace(fortisiem_incidents=fortisiem), MagicMock()
    )
    assert client.session.auth == ("super/api-user", "pw")


def test_get_incidents_list_response():
    client = _make_client()
    client.session.request.return_value = _response([{"incidentId": 1}])
    assert client.get_incidents("2026-01-01T00:00:00Z") == [{"incidentId": 1}]


def test_get_incidents_dict_response():
    client = _make_client()
    client.session.request.return_value = _response({"incidents": [{"incidentId": 2}]})
    assert client.get_incidents("2026-01-01T00:00:00Z") == [{"incidentId": 2}]


def test_get_incidents_unexpected_shape_returns_empty():
    client = _make_client()
    client.session.request.return_value = _response({"unexpected": True})
    assert client.get_incidents("2026-01-01T00:00:00Z") == []


def test_get_incidents_raises_on_request_failure():
    # A fetch failure must raise (not return []), so the connector does not advance
    # its state past a window it never actually fetched.
    client = _make_client()
    client.session.request.side_effect = requests.RequestException("boom")
    with patch("fortisiem_client.api_client.time.sleep"):
        with pytest.raises(FortiSIEMClientError):
            client.get_incidents("2026-01-01T00:00:00Z")


def test_get_incidents_raises_on_non_json_response():
    client = _make_client()
    bad = _response(None)
    bad.json.side_effect = ValueError("not json")
    client.session.request.return_value = bad
    with pytest.raises(FortiSIEMClientError):
        client.get_incidents("2026-01-01T00:00:00Z")


def test_request_retries_on_rate_limit():
    client = _make_client()
    client.session.request.side_effect = [
        _response({}, status=429),
        _response([], status=200),
    ]
    with patch("fortisiem_client.api_client.time.sleep") as sleep:
        result = client._request("get", "/phoenix/rest/pub/incident")
    assert result is not None
    assert client.session.request.call_count == 2
    sleep.assert_called_once()


def test_request_fails_fast_on_4xx_without_retry():
    client = _make_client()
    response = _response({}, status=404)
    response.raise_for_status.side_effect = requests.HTTPError("404")
    client.session.request.return_value = response
    with patch("fortisiem_client.api_client.time.sleep") as sleep:
        result = client._request("get", "/phoenix/rest/pub/incident")
    assert result is None
    assert client.session.request.call_count == 1
    sleep.assert_not_called()


def test_request_retries_on_server_error():
    client = _make_client()
    client.session.request.side_effect = [
        _response({}, status=500),
        _response([], status=200),
    ]
    with patch("fortisiem_client.api_client.time.sleep") as sleep:
        result = client._request("get", "/phoenix/rest/pub/incident")
    assert result is not None
    assert client.session.request.call_count == 2
    sleep.assert_called_once()
