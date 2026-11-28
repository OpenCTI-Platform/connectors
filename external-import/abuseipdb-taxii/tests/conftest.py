import json
import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from abuseipdb_taxii_client import TaxiiPage  # noqa: E402
from connector import ConnectorSettings, ConnectorState  # noqa: E402
from connector.data_processors import TaxiiFeedProcessor  # noqa: E402

CONFIGURED_COLLECTION_ID = "configured-collection-id"

VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {
        "id": "a4d023e5-8a43-4630-983f-35d73b356e82",
        "name": "AbuseIPDB TAXII",
        "scope": "abuseipdb-taxii",
        "log_level": "error",
        "duration_period": "PT1H",
    },
    "abuseipdb_taxii": {
        "url": "https://taxii.abuseipdb.com/taxii2/abuseipdb-taxii2/",
        "username": "test-user",
        "password": "test-password",
        "collection_id": CONFIGURED_COLLECTION_ID,
        "import_since": "2026-08-19T04:00:00Z",
        "page_size": 100,
        "verify_ssl": True,
        "request_timeout_seconds": 60,
    },
}

COLLECTION_ID = "fake-collection-id"
TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"


def make_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Build `ConnectorSettings` from a dict instead of env/config files."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


@pytest.fixture
def settings() -> ConnectorSettings:
    return make_settings(VALID_SETTINGS_DICT)


def make_response(
    status: int = 200,
    body: Any = None,
    headers: dict[str, str] | None = None,
    *,
    raw_body: bytes | None = None,
) -> requests.Response:
    """Build a real `requests.Response`, so headers use its case-insensitive mapping."""
    response = requests.Response()
    response.status_code = status
    response.headers.update(
        headers if headers is not None else {"Content-Type": TAXII_CONTENT_TYPE}
    )
    response._content = raw_body if raw_body is not None else json.dumps(body).encode()
    response.encoding = "utf-8"
    return response


class FakeTaxiiClient:
    """Serve a scripted sequence of pages or errors in place of the HTTP client."""

    def __init__(self, script: list[TaxiiPage | Exception]) -> None:
        self.script = list(script)
        self.requests: list[dict[str, Any]] = []
        self.configured_id: str | None = None

    def discover_collection_id(self, configured_id: str | None) -> str:
        self.configured_id = configured_id
        return COLLECTION_ID

    def get_objects_page(
        self,
        collection_id: str,
        *,
        added_after: str | None,
        next_cursor: str | None,
        limit: int,
    ) -> TaxiiPage:
        self.requests.append(
            {"added_after": added_after, "next_cursor": next_cursor, "limit": limit}
        )
        if not self.script:
            raise AssertionError("FakeTaxiiClient script is exhausted")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def make_processor(
    script: list[TaxiiPage | Exception],
    *,
    state: ConnectorState | None = None,
    helper: MagicMock | None = None,
) -> TaxiiFeedProcessor:
    """Build a `TaxiiFeedProcessor` wired to a mock helper and a `FakeTaxiiClient`."""
    processor = TaxiiFeedProcessor()
    processor.inject_dependencies(
        settings=make_settings(VALID_SETTINGS_DICT),
        helper=helper if helper is not None else MagicMock(),
        state=state if state is not None else ConnectorState(),
    )
    processor.post_init()
    processor.client = FakeTaxiiClient(script)
    processor.logger = MagicMock()
    return processor
