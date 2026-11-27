from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from src.connector.models import ConfigLoader
from src.connector.sekoia import SekoiaConnector

DEFAULT_SCOPE = (
    "identity,attack-pattern,course-of-action,intrusion-set,malware,tool,report,"
    "location,vulnerability,indicator,campaign,infrastructure,relationship"
)


def _connector(connect_scope) -> SekoiaConnector:
    config = MagicMock()
    config.sekoia.limit = 200
    config.sekoia.base_url = "https://api.sekoia.io"
    config.sekoia.collection = "collection-id"
    helper = MagicMock()
    helper.connect_scope = connect_scope
    return SekoiaConnector(config, helper)


def _response(status_code=200, payload=None) -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response.url = "https://api.sekoia.io/v2/inthreat/collections/x/objects"
    response._content = b"{}" if payload is None else payload
    return response


def test_default_settings_give_the_scope_as_a_list(monkeypatch):
    """pycti reads the scope from the dumped settings when CONNECTOR_SCOPE is not set."""
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("SEKOIA_API_KEY", "test-api-key")
    monkeypatch.delenv("CONNECTOR_SCOPE", raising=False)

    scope = ConfigLoader().model_dump_pycti()["connector"]["scope"]

    assert scope == DEFAULT_SCOPE.split(",")


@pytest.mark.parametrize(
    "connect_scope",
    [
        DEFAULT_SCOPE.split(","),  # Settings default or config.yml
        DEFAULT_SCOPE,  # CONNECTOR_SCOPE environment variable
    ],
)
def test_requested_types_is_a_comma_separated_string(connect_scope):
    assert _connector(connect_scope).requested_types == DEFAULT_SCOPE


def test_requested_types_with_an_empty_list_is_empty():
    assert _connector([]).requested_types == ""


@pytest.mark.parametrize("connect_scope", [DEFAULT_SCOPE.split(","), DEFAULT_SCOPE])
def test_run_sends_a_single_match_type_parameter(connect_scope):
    connector = _connector(connect_scope)

    with patch(
        "src.connector.sekoia.requests.get",
        return_value=_response(payload=b'{"items": [], "next_cursor": "same"}'),
    ) as get:
        cursor = connector._run("same", "work-id")

    assert cursor == "same"
    params = get.call_args.kwargs["params"]
    url = requests.Request("GET", get.call_args.args[0], params=params).prepare().url
    assert parse_qs(urlparse(url).query)["match[type]"] == [DEFAULT_SCOPE]


def test_run_without_scope_sends_no_match_type_parameter():
    connector = _connector([])

    with patch(
        "src.connector.sekoia.requests.get",
        return_value=_response(payload=b'{"items": [], "next_cursor": "same"}'),
    ) as get:
        connector._run("same", "work-id")

    assert "match[type]" not in get.call_args.kwargs["params"]


def test_http_error_status_is_logged():
    connector = _connector(DEFAULT_SCOPE)

    with patch(
        "src.connector.sekoia.requests.get", return_value=_response(status_code=400)
    ):
        assert connector._send_request("https://api.sekoia.io/x") is None

    connector.helper.connector_logger.error.assert_called_once_with(
        "Request failed with status: 400"
    )
