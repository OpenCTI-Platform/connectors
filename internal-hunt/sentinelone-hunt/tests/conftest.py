import copy
import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from sentinelone_hunt import ConnectorSettings, SentinelOneHuntConnector  # noqa: E402

CONSOLE_URL = "https://tenant.sentinelone.net"
QUERIES_URL = f"{CONSOLE_URL}/sdl/v2/api/queries"
FORWARD_TAG = "node-7"

VALID_SETTINGS: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {"id": "connector-id", "log_level": "error"},
    "sentinelone_hunt": {"api_url": CONSOLE_URL, "api_token": "s1-token"},
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
        "name": "SentinelOne Singularity",
    },
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


def done(columns: list[str], values: list[list[Any]], **extra: Any) -> dict[str, Any]:
    """Build the answer of a completed PowerQuery."""
    return {
        "id": extra.pop("query_id", "q1"),
        "stepsCompleted": 1,
        "stepsTotal": 1,
        "data": {
            "columns": [{"name": name} for name in columns],
            "values": values,
            "matchCount": len(values),
        },
        **extra,
    }


def running(query_id: str = "q1", completed: int = 0) -> dict[str, Any]:
    """Build the answer of a PowerQuery still running."""
    return {"id": query_id, "stepsCompleted": completed, "stepsTotal": 2}


def mock_query(
    requests_mock,
    launch: dict[str, Any],
    polls: list[dict[str, Any]] | None = None,
    query_id: str = "q1",
):
    """Mock the launch, the status answers and the deletion of a query."""
    requests_mock.post(
        QUERIES_URL, json=launch, headers={"X-Dataset-Query-Forward-Tag": FORWARD_TAG}
    )
    if polls:
        requests_mock.get(
            f"{QUERIES_URL}/{query_id}", [{"json": answer} for answer in polls]
        )
    return requests_mock.delete(f"{QUERIES_URL}/{query_id}", status_code=204)


def launched_queries(requests_mock) -> list[str]:
    """Return the PowerQueries launched, in order."""
    return [
        request.json()["pq"]["query"]
        for request in requests_mock.request_history
        if request.method == "POST"
    ]


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

    def _make(overrides: dict[str, Any] | None = None) -> SentinelOneHuntConnector:
        connector = SentinelOneHuntConnector(make_settings(overrides))
        connector._helper = helper
        connector._logger = MagicMock()
        connector.post_init()
        return connector

    return _make


@pytest.fixture
def hunt_event() -> dict[str, Any]:
    """A fresh hunt run message."""
    return copy.deepcopy(HUNT_EVENT)
