import json
from unittest.mock import Mock, patch

import pytest
from requests.exceptions import ConnectionError, HTTPError, RetryError, Timeout

# ---------------------------------------------------------------------------
# set_oauth_token
# ---------------------------------------------------------------------------


def test_set_oauth_token_success(client):
    mock_response = Mock()
    mock_response.text = json.dumps({"access_token": "my-bearer-token"})
    with patch("requests.post", return_value=mock_response):
        client.set_oauth_token()
    assert client.session.headers.get("Authorization") == "my-bearer-token"


def test_set_oauth_token_missing_access_token_raises(client):
    mock_response = Mock()
    mock_response.text = json.dumps({"error": "invalid_client"})
    with patch("requests.post", return_value=mock_response):
        with pytest.raises(ValueError, match="Failed generating oauth token"):
            client.set_oauth_token()


def test_set_oauth_token_request_exception_raises(client):
    with patch("requests.post", side_effect=Exception("network error")):
        with pytest.raises(ValueError, match="Failed generating oauth token"):
            client.set_oauth_token()


# ---------------------------------------------------------------------------
# retries_builder
# ---------------------------------------------------------------------------


def test_retries_builder_installs_https_adapter(client):
    from requests.adapters import HTTPAdapter

    client.retries_builder()
    adapter = client.session.get_adapter("https://graph.microsoft.com")
    assert isinstance(adapter, HTTPAdapter)


# ---------------------------------------------------------------------------
# query_builder
# ---------------------------------------------------------------------------


def test_query_builder_returns_prepared_request(client):
    req = client.query_builder("2024-01-01T00:00:00+00:00")
    assert req.url is not None
    assert "graph.microsoft.com" in req.url
    assert "security/incidents" in req.url
    assert "%24expand" in req.url or "$expand" in req.url


def test_query_builder_includes_filter_param(client):
    req = client.query_builder("2024-06-01T00:00:00+00:00")
    assert "lastUpdateDateTime" in req.url


# ---------------------------------------------------------------------------
# pagination_incidents
# ---------------------------------------------------------------------------


def test_pagination_incidents_single_page(client):
    mock_resp = Mock()
    mock_resp.raise_for_status = Mock()
    mock_resp.json.return_value = {"value": [{"id": "inc-1"}, {"id": "inc-2"}]}
    client.session.get = Mock(return_value=mock_resp)
    result = client.pagination_incidents("https://example.com/incidents")
    assert len(result) == 2


def test_pagination_incidents_multiple_pages(client):
    page1 = Mock()
    page1.raise_for_status = Mock()
    page1.json.return_value = {
        "value": [{"id": "inc-1"}],
        "@odata.nextLink": "https://example.com/incidents?page=2",
    }
    page2 = Mock()
    page2.raise_for_status = Mock()
    page2.json.return_value = {"value": [{"id": "inc-2"}]}
    client.session.get = Mock(side_effect=[page1, page2])
    result = client.pagination_incidents("https://example.com/incidents")
    assert len(result) == 2


def test_pagination_incidents_retry_error_returns_empty(client):
    client.session.get = Mock(side_effect=RetryError("max retries exceeded"))
    result = client.pagination_incidents("https://example.com/incidents")
    assert result == []
    client.helper.connector_logger.error.assert_called()


def test_pagination_incidents_http_error_returns_empty(client):
    client.session.get = Mock(side_effect=HTTPError("404 Not Found"))
    result = client.pagination_incidents("https://example.com/incidents")
    assert result == []
    client.helper.connector_logger.error.assert_called()


def test_pagination_incidents_timeout_returns_empty(client):
    client.session.get = Mock(side_effect=Timeout("request timed out"))
    result = client.pagination_incidents("https://example.com/incidents")
    assert result == []
    client.helper.connector_logger.error.assert_called()


def test_pagination_incidents_connection_error_returns_empty(client):
    client.session.get = Mock(side_effect=ConnectionError("connection refused"))
    result = client.pagination_incidents("https://example.com/incidents")
    assert result == []
    client.helper.connector_logger.error.assert_called()


def test_pagination_incidents_generic_exception_returns_empty(client):
    client.session.get = Mock(side_effect=Exception("unexpected failure"))
    result = client.pagination_incidents("https://example.com/incidents")
    assert result == []
    client.helper.connector_logger.error.assert_called()


# ---------------------------------------------------------------------------
# get_incidents
# ---------------------------------------------------------------------------


def test_get_incidents_returns_list(client):
    page_resp = Mock()
    page_resp.raise_for_status = Mock()
    page_resp.json.return_value = {"value": [{"id": "inc-1"}]}
    client.session.get = Mock(return_value=page_resp)
    # 2024-01-01 00:00:00 UTC
    result = client.get_incidents(1704067200)
    assert isinstance(result, list)
    assert len(result) == 1


def test_get_incidents_returns_empty_on_exception(client):
    with patch.object(client, "retries_builder", side_effect=Exception("boom")):
        result = client.get_incidents(1704067200)
    assert result == []
    client.helper.connector_logger.error.assert_called()
