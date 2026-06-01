from unittest.mock import MagicMock

import pytest
import requests
from hybrid_analysis_client import HybridAnalysisAPIError, HybridAnalysisClient


@pytest.fixture
def mock_helper():
    """Provide a mocked connector helper with a mocked logger."""
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    return helper


@pytest.fixture
def client(mock_helper):
    """Provide a HybridAnalysisClient configured with default test values."""
    return HybridAnalysisClient(
        helper=mock_helper,
        token="test-token",
        environment_id="110",
    )


def test_hybrid_analysis_client_init_sets_expected_attributes(client, mock_helper):
    """Client initialization should populate core configuration and headers."""
    # Given: valid arguments for client
    # When: the client is instantiated
    client = HybridAnalysisClient(
        helper=mock_helper, token="any-token", environment_id="160"
    )

    # Then: the client has the expected attributes
    assert client.base_url == "https://hybrid-analysis.com/api/v2"
    assert client.environment_id == "160"
    assert client.session.headers.get("api-key") == "any-token"
    assert client.session.headers.get("accept") == "application/json"
    assert "OpenCTI" in client.session.headers.get("user-agent", "")
    assert client.helper is mock_helper
    assert isinstance(client.session, requests.Session)


def test_submit_request_forwards_kwargs(client):
    """_submit_request should forward method, URL and kwargs to requests.Session."""
    # Given: a mocked session request returning a successful response
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    client.session.request = MagicMock(return_value=mock_response)

    # When: _submit_request is called with POST and request data
    result = client._submit_request(
        "POST", "/submit/url", data={"url": "http://example.com"}
    )

    # Then: the session request receives the expected URL and payload
    client.session.request.assert_called_once_with(
        "POST",
        "https://hybrid-analysis.com/api/v2/submit/url",
        data={"url": "http://example.com"},
    )
    assert result is mock_response


def test_submit_request_returns_response(client):
    """_submit_request should return the response object on success."""
    # Given: a mocked successful response from the session
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    client.session.request = MagicMock(return_value=mock_response)

    # When: _submit_request is executed on a valid endpoint
    result = client._submit_request("GET", "/test/endpoint")

    # Then: the original response object is returned unchanged
    assert result is mock_response


def test_submit_request_wraps_http_error(client):
    """_submit_request should wrap HTTPError into HybridAnalysisAPIError."""
    # Given: a session response that raises requests.HTTPError
    http_error = requests.HTTPError()
    http_error.response = MagicMock()
    http_error.response.status_code = 500
    http_error.response.reason = "Internal Server Error"
    http_error.response.json.return_value = {"message": "Unexpected failure"}

    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = http_error
    client.session.request = MagicMock(return_value=mock_response)

    # When: _submit_request triggers the failing HTTP call
    with pytest.raises(HybridAnalysisAPIError) as exc_info:
        client._submit_request("POST", "/submit/url")

    # Then: a HybridAnalysisAPIError is raised with status and API message details
    assert "500" in str(exc_info.value)
    assert "Internal Server Error" in str(exc_info.value)
    assert "Unexpected failure" in str(exc_info.value)


def test_get_report_state_succeeds(client):
    """get_report_state should call the expected endpoint and return JSON payload."""
    # Given: _submit_request mocked to return a state payload
    mock_response = MagicMock()
    mock_response.json.return_value = {"state": "IN_QUEUE"}
    client._submit_request = MagicMock(return_value=mock_response)

    # When: get_report_state is called with a report id
    result = client.get_report_state("report-123")

    # Then: it calls the state endpoint and returns the parsed JSON
    client._submit_request.assert_called_once_with("GET", "/report/report-123/state")
    assert result == {"state": "IN_QUEUE"}


def test_get_report_summary_succeeds(client):
    """get_report_summary should call the expected endpoint and return JSON payload."""
    # Given: _submit_request mocked to return a summary payload
    mock_response = MagicMock()
    mock_response.json.return_value = {"verdict": "no specific threat", "sha256": "abc"}
    client._submit_request = MagicMock(return_value=mock_response)

    # When: get_report_summary is called with a report id
    result = client.get_report_summary("report-456")

    # Then: it calls the summary endpoint and returns the parsed JSON
    client._submit_request.assert_called_once_with("GET", "/report/report-456/summary")
    assert result == {"verdict": "no specific threat", "sha256": "abc"}


def test_search_hash_succeeds(client):
    """search_hash should call hash search endpoint and return parsed response."""
    # Given: _submit_request mocked to return one matching report
    mock_response = MagicMock()
    mock_response.json.return_value = {"reports": [{"id": "abc"}]}
    client._submit_request = MagicMock(return_value=mock_response)

    # When: search_hash is called with a known hash
    result = client.search_hash("abc123")

    # Then: it queries the hash endpoint and returns the parsed JSON
    client._submit_request.assert_called_once_with(
        "GET", "/search/hash", params={"hash": "abc123"}
    )
    assert result == {"reports": [{"id": "abc"}]}


def test_search_hash_catches_hash_not_found(client):
    """search_hash should return None when API reports unknown hash."""
    # Given: _submit_request raising a hash-not-found API error
    client._submit_request = MagicMock(
        side_effect=HybridAnalysisAPIError("Requested hash not found in database")
    )

    # When: search_hash is called with an unknown hash
    result = client.search_hash("notfound")

    # Then: the client returns None instead of propagating the error
    assert result is None


def test_search_hash_reraises_error_unrelated_to_hash_not_found(client):
    """search_hash should re-raise API errors that are not hash-not-found."""
    # Given: _submit_request raising a generic API error
    client._submit_request = MagicMock(
        side_effect=HybridAnalysisAPIError("500 (Internal Server Error) - Unexpected")
    )

    # When: search_hash is called, then the same API error is re-raised
    with pytest.raises(HybridAnalysisAPIError):
        client.search_hash("hash123")


def test_submit_url_succeeds(client):
    """submit_url should send expected payload and return JSON response."""
    # Given: _submit_request mocked to return a submission job id
    mock_response = MagicMock()
    mock_response.json.return_value = {"job_id": "job-456"}
    client._submit_request = MagicMock(return_value=mock_response)

    # When: submit_url is called with an observable URL
    result = client.submit_url("http://malicious.example.com")

    # Then: it posts the expected payload and returns the parsed JSON
    client._submit_request.assert_called_once_with(
        "POST",
        "/submit/url",
        data={
            "url": "http://malicious.example.com",
            "environment_id": "110",
        },
    )
    assert result == {"job_id": "job-456"}


def test_submit_file_succeeds(client):
    """submit_file should send expected multipart payload and return JSON response."""
    # Given: _submit_request mocked to return a submission job id
    mock_response = MagicMock()
    mock_response.json.return_value = {"job_id": "job-789"}
    client._submit_request = MagicMock(return_value=mock_response)

    # When: submit_file is called with file name and bytes
    result = client.submit_file("malware.exe", b"file_content_bytes")

    # Then: it posts multipart data and returns the parsed JSON
    client._submit_request.assert_called_once_with(
        "POST",
        "/submit/file",
        data={"environment_id": "110"},
        files={"file": ("malware.exe", b"file_content_bytes")},
    )
    assert result == {"job_id": "job-789"}
