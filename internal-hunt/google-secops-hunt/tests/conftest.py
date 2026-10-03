import copy
import os
import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from google_secops_hunt import (  # noqa: E402
    ConnectorSettings,
    GoogleSecopsHuntConnector,
)

API_URL = "https://europe-chronicle.googleapis.com"
INSTANCE_PATH = "/v1alpha/projects/hunt-project/locations/europe/instances/instance-1"
UDM_SEARCH_URL = f"{API_URL}{INSTANCE_PATH}:udmSearch"
RUN_RULE_URL = f"{API_URL}{INSTANCE_PATH}/legacy:legacyRunTestRule"

VALID_SETTINGS: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {"id": "connector-id", "log_level": "error"},
    "google_secops_hunt": {
        "project_id": "hunt-project",
        "project_region": "europe",
        "project_instance": "instance-1",
        "private_key": "-----BEGIN PRIVATE KEY-----\\nkey\\n-----END PRIVATE KEY-----\\n",
        "private_key_id": "key-id",
        "client_email": "hunter@hunt-project.iam.gserviceaccount.com",
        "client_id": "1234567890",
    },
}

SIGMA_RULE = """
title: Encoded PowerShell
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: ' -enc '
  condition: selection
"""

HUNT_EVENT: dict[str, Any] = {
    "event_type": "INTERNAL_HUNT",
    "mode": "execute",
    "hunt_run": {"id": "run-1", "attempt": 1, "trigger": "manual"},
    "hunt": {
        "id": "hunt-1",
        "standard_id": "hunt--0b7c7d6b-1f47-4c1f-9b37-6b0b6d7a0001",
        "name": "Encoded PowerShell",
        "sigma_rule": SIGMA_RULE,
        "expected_observables": ["IPv4-Addr", "Domain-Name"],
        "object_marking_refs": [
            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
        ],
        "created_by_ref": "identity--7b82b010-b1c0-4dae-981f-7756374a17df",
        "techniques": [
            {"standard_id": "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736"}
        ],
        "indicators": [
            {"standard_id": "indicator--a1b2c3d4-0000-4000-8000-000000000001"}
        ],
    },
    "time_window": {"start": "2026-10-03T00:00:00Z", "end": "2026-10-04T00:00:00Z"},
    "limits": {"max_results": 100, "timeout_seconds": 30},
    "security_platform": {
        "id": "platform-1",
        "standard_id": "identity--5b1a4c88-5ac7-4c7f-9d8c-9a5f2e8d7c01",
        "name": "Google SecOps",
    },
}


class FakeCredentials:
    """Service account credentials issuing a fixed access token."""

    def __init__(self, valid: bool = False, error: Exception | None = None) -> None:
        self.valid = valid
        self.token: str | None = "token-0" if valid else None
        self.error = error
        self.requests: list[Any] = []

    def refresh(self, request: Any) -> None:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        self.token = f"token-{len(self.requests)}"
        self.valid = True


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


def udm_event(timestamp: str, **fields: Any) -> dict[str, Any]:
    """Build a UDM search event."""
    return {
        "name": "projects/p/locations/l/instances/i/events/e1",
        "udm": {"metadata": {"event_timestamp": timestamp, "id": "abc"}, **fields},
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
    """Factory of started connectors with a mocked pycti helper and credentials."""

    def _make(overrides: dict[str, Any] | None = None) -> GoogleSecopsHuntConnector:
        connector = GoogleSecopsHuntConnector(make_settings(overrides))
        connector._helper = helper
        connector._logger = MagicMock()
        with patch.object(
            GoogleSecopsHuntConnector,
            "build_credentials",
            return_value=FakeCredentials(),
        ):
            connector.post_init()
        return connector

    return _make


@pytest.fixture
def hunt_event() -> dict[str, Any]:
    """A fresh hunt run message."""
    return copy.deepcopy(HUNT_EVENT)
