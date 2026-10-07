from unittest.mock import MagicMock, patch

import connector
import pytest
import requests
from cyfirma_client import CyfirmaClient
from pydantic import HttpUrl

# Constants for API paths and parameters
_BASE_PREFIX_PATH = "/api/ex/v3/da"
_STIX_PATH = "/stix/2.1"
_IOC_TAILORED_PATH = f"{_BASE_PREFIX_PATH}{_STIX_PATH}/indicators/tailored"
_IOC_GENERIC_PATH = f"{_BASE_PREFIX_PATH}{_STIX_PATH}/indicators/all"


@pytest.fixture
def mock_helper():
    return MagicMock()


@pytest.fixture
def client(mock_helper):
    return CyfirmaClient(
        helper=mock_helper,
        base_url=HttpUrl("https://api.cyfirma.com"),
        api_key="test_key",
        tailored_iocs=True,
        tailored_vulnerabilities=True,
        last_run="2023-01-01T00:00:00Z",
    )


def test_cyfirma_client_get_entities_success(client, mock_helper):
    with patch.object(client, "_request_data") as mock_request:
        mock_request.side_effect = [
            {"objects": [{"id": "indicator--1"}]},
            {"objects": []},
            {"objects": []},
        ]

        res = client.get_entities()
        assert res == [{"id": "indicator--1"}]
        mock_helper.connector_logger.info.assert_called()


@pytest.mark.parametrize(
    "error",
    [
        requests.ConnectionError("API connection error"),
        requests.Timeout("timed out"),
        requests.HTTPError("500 Server Error"),
    ],
)
def test_cyfirma_client_get_entities_propagates_request_errors(client, error):
    with patch.object(client, "_request_data", side_effect=error):
        with pytest.raises(requests.RequestException):
            client.get_entities()


def test_cyfirma_client_get_entities_does_not_return_partial_data_on_failure(client):
    # First page succeeds, second page fails: the caller must see the error,
    # not a truncated list that looks like a complete import.
    with patch.object(client, "_request_data") as mock_request:
        mock_request.side_effect = [
            {"objects": [{"id": "indicator--1"}]},
            requests.RequestException("API connection error"),
        ]

        with pytest.raises(requests.RequestException):
            client.get_entities()


def test_request_data_logs_and_reraises(client, mock_helper):
    with patch.object(
        client.session, "get", side_effect=requests.RequestException("boom")
    ):
        with pytest.raises(requests.RequestException):
            client._request_data(_IOC_TAILORED_PATH)

    mock_helper.connector_logger.error.assert_called()


def test_request_data_raises_on_http_error_status(client):
    response = MagicMock()
    response.raise_for_status.side_effect = requests.HTTPError("500 Server Error")

    with patch.object(client.session, "get", return_value=response):
        with pytest.raises(requests.HTTPError):
            client._request_data(_IOC_TAILORED_PATH)
