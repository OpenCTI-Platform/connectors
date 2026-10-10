import copy
import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from infrastructure_tracker import (  # noqa: E402
    ConnectorSettings,
    InfrastructureTrackerConnector,
)

CENSYS_URL = "https://api.platform.censys.io/v3/global/search/query"
SILENTPUSH_URL = (
    "https://api.silentpush.com/api/v1/merge-api/explore/scandata/search/raw"
)
URLSCAN_URL = "https://urlscan.io/api/v1/search/"
SCOUT_URL = "https://scout.cymru.com/api/scout/search"
INTERNETDB_URL = "https://internetdb.shodan.io"

JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
CERT_SHA256 = "87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c"
CERT_SUBJECT = "CN=Major Cobalt Strike, OU=AdvancedPenTesting, O=cobaltstrike"

VALID_SETTINGS: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {"id": "connector-id", "log_level": "error"},
    "infrastructure_tracker": {
        "censys_token": "censys-token",
        "censys_organisation_id": "org-1",
        "internetdb_enabled": False,
    },
}

RULE = f"""
fingerprints:
  - kind: jarm
    value: {JARM}
  - kind: certificate_subject
    value: "{CERT_SUBJECT}"
"""

TARGETS = [
    {
        "standard_id": "intrusion-set--b0f2e3c8-7c4e-4b5e-9c0d-1a2b3c4d5e6f",
        "entity_type": "Intrusion-Set",
        "name": "APT Example",
    },
    {
        "standard_id": "malware--c1a2b3d4-0000-4000-8000-000000000002",
        "entity_type": "Malware",
        "name": "Cobalt Strike",
    },
]

HUNT_EVENT: dict[str, Any] = {
    "event_type": "INTERNAL_HUNT",
    "mode": "execute",
    "hunt_run": {"id": "run-1", "attempt": 1, "trigger": "schedule"},
    "hunt": {
        "id": "hunt-1",
        "standard_id": "hunt--0b7c7d6b-1f47-4c1f-9b37-6b0b6d7a0001",
        "name": "Cobalt Strike team servers",
        "hunt_type": "infrastructure",
        "native_query": {"platform": "internet", "language": "internet", "query": RULE},
        "expected_observables": [],
        "object_marking_refs": [
            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
        ],
        "created_by_ref": "identity--7b82b010-b1c0-4dae-981f-7756374a17df",
        "targets": TARGETS,
    },
    "time_window": {"start": "2026-10-03T00:00:00Z", "end": "2026-10-04T00:00:00Z"},
    "limits": {"max_results": 100, "timeout_seconds": 30},
}


def make_settings(overrides: dict[str, Any] | None = None) -> ConnectorSettings:
    """Build connector settings from the valid settings and namespace overrides."""
    values = copy.deepcopy(VALID_SETTINGS)
    for namespace, items in (overrides or {}).items():
        values.setdefault(namespace, {}).update(items)

    class _Settings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _: Any, handler: Any) -> Any:
            return handler(values)

    return _Settings()


def censys_host(
    ip: str,
    names: list[str] | None = None,
    jarm: str = JARM,
    cert: str | None = CERT_SHA256,
    scan_time: str = "2026-10-03T08:00:00Z",
) -> dict[str, Any]:
    """Build a Censys host hit."""
    service: dict[str, Any] = {
        "port": 443,
        "jarm": {"fingerprint": jarm},
        "tls": {"ja4s": "t130200_1302_a56c5b993250"},
        "banner_hash_sha256": "b" * 64,
        "endpoints": [
            {"http": {"html_title": "Not Found", "body_hash_sha256": "c" * 64}}
        ],
        "scan_time": scan_time,
    }
    if cert:
        service["cert"] = {
            "fingerprint_sha256": cert,
            "parsed": {
                "subject_dn": CERT_SUBJECT,
                "issuer_dn": CERT_SUBJECT,
                "ja4x": "a373a9f83c6b_2bab15409345_7bf9a7bf7029",
            },
        }
    return {
        "host_v1": {
            "resource": {
                "ip": ip,
                "autonomous_system": {"asn": 20473, "name": "AS-CHOOPA"},
                "dns": {"names": names or []},
                "services": [service],
            }
        }
    }


def censys_answer(
    hits: list[dict[str, Any]], next_token: str = "", total: int | None = None
) -> dict[str, Any]:
    """Build a Censys search answer."""
    return {
        "result": {
            "hits": hits,
            "next_page_token": next_token,
            "total_hits": len(hits) if total is None else total,
        }
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

    def _make(
        overrides: dict[str, Any] | None = None,
    ) -> InfrastructureTrackerConnector:
        connector = InfrastructureTrackerConnector(make_settings(overrides))
        connector._helper = helper
        connector._logger = MagicMock()
        connector.post_init()
        return connector

    return _make


@pytest.fixture
def hunt_event() -> dict[str, Any]:
    """A fresh hunt run message."""
    return copy.deepcopy(HUNT_EVENT)
