import copy
import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from opensearch_ocsf_hunt import (  # noqa: E402
    ConnectorSettings,
    OpenSearchOcsfHuntConnector,
)

OS_URL = "https://opensearch.example.com:9200"
PPL_URL = f"{OS_URL}/_plugins/_ppl"
SEARCH_URL = f"{OS_URL}/ocsf-*/_search"

VALID_SETTINGS: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {"id": "connector-id", "log_level": "error"},
    "opensearch_ocsf_hunt": {
        "url": OS_URL,
        "username": "hunter",
        "password": "secret",
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
        "name": "OpenSearch",
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


def ppl_answer(columns: list[str], rows: list[list[Any]]) -> dict[str, Any]:
    """Build a PPL answer."""
    return {
        "schema": [{"name": name, "type": "string"} for name in columns],
        "datarows": rows,
        "total": len(rows),
        "size": len(rows),
    }


def count_answer(count: int) -> dict[str, Any]:
    """Build the answer of a PPL ``stats count()`` query."""
    return ppl_answer(["opencti_hit_count"], [[count]])


def hits_answer(
    sources: list[dict[str, Any]],
    total: int | None = None,
    timed_out: bool = False,
    failed_shards: int = 0,
) -> dict[str, Any]:
    """Build a search answer holding documents."""
    return {
        "timed_out": timed_out,
        "_shards": {"total": 2, "failed": failed_shards},
        "hits": {
            "total": {
                "value": len(sources) if total is None else total,
                "relation": "eq",
            },
            "hits": [{"_index": "ocsf-1", "_source": source} for source in sources],
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

    def _make(overrides: dict[str, Any] | None = None) -> OpenSearchOcsfHuntConnector:
        connector = OpenSearchOcsfHuntConnector(make_settings(overrides))
        connector._helper = helper
        connector._logger = MagicMock()
        connector.post_init()
        return connector

    return _make


@pytest.fixture
def hunt_event() -> dict[str, Any]:
    """A fresh hunt run message."""
    return copy.deepcopy(HUNT_EVENT)
