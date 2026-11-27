import copy
import json
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

# Placeholder host: every request in these tests goes to FakeSekoiaApi.
SEKOIA_URL = "https://sekoia.test"
COLLECTION = "collection-id"
COLLECTION_PATH = f"/v2/inthreat/collections/{COLLECTION}/objects"
CURSOR = "cursor-from-state"
NEXT_CURSOR = "cursor-from-sekoia"

IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--06042e40-c888-44e5-97d5-0a1e5233cadd",
    "created": "2026-11-20T13:42:39.488Z",
    "modified": "2026-11-20T13:42:39.488Z",
    "name": "Example Organization",
    "identity_class": "organization",
}
NOTE = {
    "type": "note",
    "spec_version": "2.1",
    "id": "note--4f1b1a0e-3c3a-4a4e-9a3e-0d5b8f2a7c11",
    "created": "2026-11-20T13:42:39.488Z",
    "modified": "2026-11-20T13:42:39.488Z",
    "content": "Out of scope",
    "object_refs": [IDENTITY["id"]],
}


def _response(status_code=200, payload=None) -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response.url = f"{SEKOIA_URL}{COLLECTION_PATH}"
    response._content = json.dumps(payload or {}).encode("utf-8")
    return response


class FakeSekoiaApi:
    """Stands in for `requests.get` on the Sekoia collection objects endpoint.

    It reproduces how the API answers since 2026-11-20: a type filter sent as
    repeated `match[type]` parameters matches nothing (empty page, cursor
    unchanged), while a comma-separated filter returns the objects of those
    types and a new cursor.
    """

    def __init__(self, objects):
        self.objects = objects
        self.queries = []

    def get(self, url, params=None, headers=None, timeout=None):
        prepared = urlparse(requests.Request("GET", url, params=params).prepare().url)
        if prepared.path != COLLECTION_PATH:
            return _response(status_code=404)

        query = parse_qs(prepared.query)
        self.queries.append(query)
        types = query.get("match[type]")
        if types is not None and len(types) > 1:
            return _response(payload={"items": [], "next_cursor": query["cursor"][0]})

        wanted = types[0].split(",") if types else None
        items = [
            copy.deepcopy(obj)
            for obj in self.objects
            if wanted is None or obj["type"] in wanted
        ]
        return _response(payload={"items": items, "next_cursor": NEXT_CURSOR})


@pytest.fixture
def sekoia_api():
    api = FakeSekoiaApi([IDENTITY, NOTE])
    with patch("src.connector.sekoia.requests.get", side_effect=api.get):
        yield api


def _connector(connect_scope) -> SekoiaConnector:
    config = MagicMock()
    config.sekoia.limit = 200
    config.sekoia.base_url = SEKOIA_URL
    config.sekoia.collection = COLLECTION
    helper = MagicMock()
    helper.connect_scope = connect_scope
    return SekoiaConnector(config, helper)


def _sent_ids(connector: SekoiaConnector) -> list[str]:
    items = connector.helper.stix2_create_bundle.call_args.args[0]
    return [item["id"] for item in items]


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


@pytest.mark.parametrize(
    "connect_scope",
    [
        DEFAULT_SCOPE.split(","),  # Settings default or config.yml
        DEFAULT_SCOPE,  # CONNECTOR_SCOPE environment variable
    ],
)
def test_run_imports_in_scope_objects_and_moves_the_cursor(sekoia_api, connect_scope):
    connector = _connector(connect_scope)

    cursor = connector._run(CURSOR, "work-id")

    assert cursor == NEXT_CURSOR
    assert sekoia_api.queries[0]["match[type]"] == [DEFAULT_SCOPE]
    assert sekoia_api.queries[0]["cursor"] == [CURSOR]
    assert _sent_ids(connector) == [IDENTITY["id"]]
    connector.helper.send_stix2_bundle.assert_called_once()
    connector.helper.set_state.assert_called_once_with({"last_cursor": NEXT_CURSOR})


def test_run_without_scope_sends_no_type_filter(sekoia_api):
    connector = _connector([])

    cursor = connector._run(CURSOR, "work-id")

    assert "match[type]" not in sekoia_api.queries[0]
    assert cursor == NEXT_CURSOR
    assert sorted(_sent_ids(connector)) == sorted([IDENTITY["id"], NOTE["id"]])


def test_http_error_status_is_logged():
    connector = _connector(DEFAULT_SCOPE)

    with patch(
        "src.connector.sekoia.requests.get", return_value=_response(status_code=400)
    ):
        assert connector._send_request(f"{SEKOIA_URL}{COLLECTION_PATH}") is None

    connector.helper.connector_logger.error.assert_called_once_with(
        "Request failed with status: 400"
    )
