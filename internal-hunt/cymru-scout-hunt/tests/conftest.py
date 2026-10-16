import copy
import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from cymru_scout_hunt import ConnectorSettings, CymruScoutHuntConnector  # noqa: E402

SEARCH_URL = "https://scout.cymru.com/api/scout/search"

JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
CERT_SUBJECT = "CN=Major Cobalt Strike, OU=AdvancedPenTesting, O=cobaltstrike"

VALID_SETTINGS: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {"id": "connector-id", "log_level": "error"},
    "cymru_scout_hunt": {"api_key": "scout-key"},
}

DOCUMENT = f"""
fingerprints:
  - kind: jarm
    value: {JARM}
  - kind: certificate_subject
    value: "{CERT_SUBJECT}"
  - kind: asn
    value: AS20473
"""

HUNT_EVENT: dict[str, Any] = {
    "event_type": "INTERNAL_HUNT",
    "mode": "execute",
    "hunt_run": {"id": "run-1", "attempt": 1, "trigger": "schedule"},
    "hunt": {
        "id": "hunt-1",
        "standard_id": "hunt--0b7c7d6b-1f47-4c1f-9b37-6b0b6d7a0001",
        "name": "Cobalt Strike team servers",
        "hunt_type": "infrastructure",
        "native_query": {
            "platform": "cymru-scout",
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
    "time_window": {"start": "2026-10-03T06:00:00Z", "end": "2026-10-03T12:00:00Z"},
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


def scout_ip(ip: str = "8.8.8.8", last_seen: str = "2026-10-03") -> dict[str, Any]:
    """Build an IP address of a Scout search answer."""
    return {
        "ip": ip,
        "tags": [
            {
                "id": 1,
                "name": "malware",
                "children": [{"id": 2, "name": "cobalt-strike", "children": None}],
            }
        ],
        "summary": {
            "last_seen": last_seen,
            "whois": {"asn": 20473, "as_name": "AS-CHOOPA"},
            "open_ports": [{"ip": ip, "port": 443, "protocol_text": "TCP"}],
            "pdns": [{"ip": ip, "domain": "c2.update-cdn.net", "event_count": 3}],
            "fingerprints": [
                {"type": "jarm", "hash": JARM},
                {"type": "favicon.murmur3", "hash": "-978864504"},
            ],
            "certs": None,
        },
    }


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

    def _make(overrides: dict[str, Any] | None = None) -> CymruScoutHuntConnector:
        connector = CymruScoutHuntConnector(make_settings(overrides))
        connector._helper = helper
        connector._logger = MagicMock()
        connector.post_init()
        return connector

    return _make


@pytest.fixture
def hunt_event() -> dict[str, Any]:
    """A fresh hunt run message."""
    return copy.deepcopy(HUNT_EVENT)
