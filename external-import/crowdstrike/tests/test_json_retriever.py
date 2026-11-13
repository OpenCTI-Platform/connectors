"""Tests for JsonRetriever."""

from unittest.mock import patch

import pytest
import requests
from crowdstrike_feeds_services.utils.json_retriever import (
    JsonRetrievalError,
    JsonRetriever,
)

URL = "https://example.com/data.json"


def make_response(status_code: int, content: bytes) -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response._content = content
    return response


@pytest.fixture
def mock_get():
    with patch(
        "crowdstrike_feeds_services.utils.json_retriever.requests.get"
    ) as mock_get:
        yield mock_get


def test_retrieve_returns_decoded_json_on_200(mock_get):
    mock_get.return_value = make_response(200, b'{"objects": []}')

    assert JsonRetriever(URL).retrieve() == {"objects": []}
    assert mock_get.call_args.args == (URL,)


@pytest.mark.parametrize("status_code", [201, 301, 404, 500])
def test_retrieve_raises_when_status_is_not_200(mock_get, status_code):
    mock_get.return_value = make_response(status_code, b"{}")

    with pytest.raises(JsonRetrievalError, match=f"HTTP {status_code}"):
        JsonRetriever(URL).retrieve()


def test_retrieve_raises_when_payload_is_not_json(mock_get):
    mock_get.return_value = make_response(200, b"<html>not json</html>")

    with pytest.raises(JsonRetrievalError, match="not valid JSON"):
        JsonRetriever(URL).retrieve()


def test_retrieve_raises_when_request_fails(mock_get):
    mock_get.side_effect = requests.ConnectionError("unreachable")

    with pytest.raises(JsonRetrievalError, match="unreachable"):
        JsonRetriever(URL).retrieve()
