# pragma: no cover
# type: ignore
"""Fixtures of the internal hunt connector tests."""

import copy
import threading
from typing import Any
from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.internal_hunt import (
    HuntResult,
    InternalHuntConnector,
    build_pipeline,
)
from connectors_sdk.settings.base_settings import BaseInternalHuntConnectorConfig
from sigma.backends.test import TextQueryTestBackend
from sigma.pipelines.test import another_test_pipeline, dummy_test_pipeline

SIGMA_RULE = """
title: Encoded PowerShell
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: ' -enc '
    DestinationIp: 8.8.8.8
  condition: selection
"""

TEST_PIPELINES = {
    "dummy": dummy_test_pipeline,
    "another": another_test_pipeline,
}

BASE_EVENT: dict[str, Any] = {
    "event_type": "INTERNAL_HUNT",
    "mode": "execute",
    "hunt_run": {"id": "run-1", "attempt": 1, "trigger": "manual"},
    "hunt": {
        "id": "hunt-1",
        "standard_id": "hunt--0b7c7d6b-1f47-4c1f-9b37-6b0b6d7a0001",
        "name": "Encoded PowerShell",
        "hypothesis": "Adversaries run encoded PowerShell.",
        "hunt_type": "telemetry",
        "sigma_rule": SIGMA_RULE,
        "native_query": None,
        "expected_observables": ["IPv4-Addr", "Domain-Name"],
        "benign_patterns": [],
        "escalation_threshold": 10,
        "object_marking_refs": [
            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
        ],
        "created_by_ref": "identity--7b82b010-b1c0-4dae-981f-7756374a17df",
        "techniques": [
            {
                "standard_id": "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736",
                "name": "PowerShell",
                "x_mitre_id": "T1059.001",
            }
        ],
        "targets": [
            {
                "standard_id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
                "entity_type": "Intrusion-Set",
                "name": "APT28",
            }
        ],
        "indicators": [
            {
                "standard_id": "indicator--a932fcc6-e032-476c-826f-cb970a5a1ade",
                "name": "8.8.8.8",
                "pattern_type": "stix",
                "pattern": "[ipv4-addr:value = '8.8.8.8']",
            }
        ],
    },
    "time_window": {
        "start": "2026-10-03T00:00:00.000Z",
        "end": "2026-10-04T00:00:00.000Z",
    },
    "limits": {
        "max_results": 100,
        "timeout_seconds": 5,
        "evidence_max_items": 5,
        "evidence_max_value_length": 16,
    },
    "security_platform": {
        "id": "platform-1",
        "standard_id": "identity--5b1a4c88-5ac7-4c7f-9d8c-9a5f2e8d7c01",
        "name": "Test SIEM",
    },
}


@pytest.fixture
def hunt_event():
    """Factory of hunt run messages, with optional overrides of the top-level and hunt keys."""

    def _make(hunt: dict | None = None, **overrides: Any) -> dict[str, Any]:
        event = copy.deepcopy(BASE_EVENT)
        event["hunt"].update(hunt or {})
        event.update(overrides)
        return event

    return _make


def make_hunt_config(**overrides: Any) -> BaseInternalHuntConnectorConfig:
    """Build a valid hunt connector configuration."""
    values = {
        "id": "connector-hunt-id",
        "name": "Test Hunt",
        "scope": ["splunk"],
        "security_platform_name": "Test SIEM",
        **overrides,
    }
    return BaseInternalHuntConnectorConfig(**values)


@pytest.fixture
def hunt_settings() -> MagicMock:
    """Mock connector settings with a real hunt connector configuration."""
    settings = MagicMock()
    settings.connector = make_hunt_config()
    settings.to_helper_config.return_value = {"connector": {"type": "INTERNAL_HUNT"}}
    return settings


@pytest.fixture
def hunt_helper() -> MagicMock:
    """Mock pycti helper exposing the hunt API."""
    helper = MagicMock()
    helper.work_id = "work-1"
    helper.connector_logger = MagicMock()
    helper.register_hunt_platform.return_value = {"id": "connector-hunt-id"}
    helper.stix2_create_bundle.return_value = '{"type": "bundle"}'
    helper.send_stix2_bundle.return_value = ["bundle-1"]
    return helper


class DummyHuntConnector(InternalHuntConnector):
    """Hunt connector executing on a fake platform with the pySigma test backend."""

    languages = ("test", "other")
    evidence_excluded_fields = frozenset({"_raw"})

    def __init__(self, settings, result: HuntResult | None = None) -> None:
        super().__init__(settings)
        self.result = result if result is not None else HuntResult()
        self.executed = []
        self.release = threading.Event()
        self.block = False
        self.timeouts = []

    def sigma_backend(self, pipeline):
        return TextQueryTestBackend(build_pipeline(pipeline, TEST_PIPELINES))

    def execute(self, native_query, time_window, limits):
        self.executed.append((native_query, time_window, limits))
        if self.block:
            self.release.wait(10)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result

    def on_timeout(self, native_query):
        self.timeouts.append(native_query)
        self.release.set()


@pytest.fixture
def connector_factory(hunt_settings, hunt_helper):
    """Factory of started dummy hunt connectors (helper already injected)."""

    def _make(result: HuntResult | None = None, settings=None) -> DummyHuntConnector:
        connector = DummyHuntConnector(settings or hunt_settings, result=result)
        connector._helper = hunt_helper
        connector._logger = MagicMock()
        return connector

    return _make
