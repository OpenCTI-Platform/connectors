import copy
import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from silentpush_hunt import ConnectorSettings, SilentPushHuntConnector  # noqa: E402

SEARCH_URL = "https://api.silentpush.com/api/v1/merge-api/explore/scandata/search/raw"

JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
CERT_SHA256 = "87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c"

VALID_SETTINGS: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {"id": "connector-id", "log_level": "error"},
    "silentpush_hunt": {"api_key": "sp-key"},
}

DOCUMENT = f"""
fingerprints:
  - kind: jarm
    value: {JARM}
  - kind: http_title
    value: Sign in
  - kind: ja4x
    value: a373a9f83c6b_2bab15409345_7bf9a7bf7029
"""

HUNT_EVENT: dict[str, Any] = {
    "event_type": "INTERNAL_HUNT",
    "mode": "execute",
    "hunt_run": {"id": "run-1", "attempt": 1, "trigger": "schedule"},
    "hunt": {
        "id": "hunt-1",
        "standard_id": "hunt--0b7c7d6b-1f47-4c1f-9b37-6b0b6d7a0001",
        "name": "Phishing kit servers",
        "hunt_type": "infrastructure",
        "native_query": {
            "platform": "silentpush",
            "language": "fingerprint",
            "query": DOCUMENT,
        },
        "expected_observables": [],
        "object_marking_refs": [
            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
        ],
        "created_by_ref": "identity--7b82b010-b1c0-4dae-981f-7756374a17df",
        "targets": [],
    },
    "time_window": {"start": "2026-10-03T00:00:00Z", "end": "2026-10-04T00:00:00Z"},
    "limits": {"max_results": 100, "timeout_seconds": 30},
}


def settings_class(overrides: dict[str, Any] | None = None) -> type[ConnectorSettings]:
    """Build a settings class loading the valid settings with namespace overrides."""
    values = copy.deepcopy(VALID_SETTINGS)
    for namespace, items in (overrides or {}).items():
        values.setdefault(namespace, {}).update(items)

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _: Any, handler: Any) -> Any:
            return handler(values)

    return FakeConnectorSettings


def make_settings(overrides: dict[str, Any] | None = None) -> ConnectorSettings:
    """Build connector settings from the valid settings and namespace overrides."""
    return settings_class(overrides)()


def scan(
    ip: str = "8.8.8.8",
    hostname: str = "c2.update-cdn.net",
    scan_date: str = "2026-10-03T08:00:00Z",
) -> dict[str, Any]:
    """Build a Silent Push web scan."""
    return {
        "ip": ip,
        "hostname": hostname,
        "domain": "update-cdn.net",
        "port": 443,
        "jarm": JARM,
        "ssl": {"SHA256": CERT_SHA256, "subject": {"common_name": "update-cdn.net"}},
        "htmltitle": "Sign in",
        "html_body_sha256": "c" * 64,
        "header": {"server": "nginx"},
        "url": f"https://{hostname}/",
        "scan_date": scan_date,
    }


def scans_answer(scans: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a Silent Push search answer."""
    return {"response": {"scandata_raw": scans}}


@pytest.fixture
def helper() -> MagicMock:
    """Mock pycti helper exposing the hunt API."""
    mock = MagicMock()
    mock.work_id = "work-1"
    mock.stix2_create_bundle.return_value = '{"type": "bundle"}'
    return mock


@pytest.fixture
def connector_factory(helper):
    """Factory of started connectors with a mocked pycti helper."""

    def _make(overrides: dict[str, Any] | None = None) -> SilentPushHuntConnector:
        connector = SilentPushHuntConnector(make_settings(overrides))
        connector._helper = helper
        connector._logger = MagicMock()
        connector.post_init()
        return connector

    return _make


@pytest.fixture
def hunt_event() -> dict[str, Any]:
    """A fresh hunt run message."""
    return copy.deepcopy(HUNT_EVENT)
