"""Regression tests: GreyNoise responses missing `internet_scanner_intelligence.classification`.

Reported in OpenCTI-Platform/connectors#7778: the connector raised
``KeyError: 'classification'`` when the GreyNoise response contained
``internet_scanner_intelligence`` without a ``classification`` key (for example, an
IP that has not been observed mass-scanning the internet). The connector should
fall back to a default value (``"unknown"``) instead of crashing.

These tests fail on the unfixed revision.
"""

from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, GreyNoiseConnector
from pycti import OpenCTIConnectorHelper


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy dependencies of OpenCTIConnectorHelper, typically API calls to OpenCTI."""

    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


class StubConnectorSettings(ConnectorSettings):
    """Subclass of `ConnectorSettings` returning a fake but valid config dict."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "auto": True,
                },
                "greynoise": {
                    "key": "ChangeMe",
                    "max_tlp": "TLP:AMBER",
                    "sighting_not_seen": False,
                    "no_sightings": False,
                },
            }
        )


def _build_connector():
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    connector = GreyNoiseConnector(config=settings, helper=helper)
    # the mocked OpenCTI API must return real (serializable) dicts, like the
    # live API does, so bundle creation can exercise the real path
    helper.api.label.read_or_create_unchecked.return_value = {"value": "test-label"}
    return connector, helper


def test_generate_stix_bundle_without_classification(
    mock_opencti_connector_helper,  # noqa: ARG001
):
    """Issue #7778 exact path: IP not found by GreyNoise, `sighting_not_seen` enabled.

    The response has no `classification` key; generating the bundle must not raise,
    and the generated description must fall back to `unknown`.
    """
    connector, _ = _build_connector()
    connector.sighting_not_seen = True

    data = {
        "ip": "203.0.113.10",
        "internet_scanner_intelligence": {"found": False},
        "business_service_intelligence": {"found": False},
    }
    stix_entity = {
        "id": "ipv4-addr--8ee5af46-71b6-4d6f-8f4a-3c3b9b6f2c11",
        "value": "203.0.113.10",
    }

    bundle = connector._generate_stix_bundle(data, stix_entity)

    assert isinstance(bundle, str) and bundle
    indicator_descriptions = [
        obj["description"]
        for obj in connector.stix_objects
        if obj.get("type") == "indicator"
    ]
    observable_descriptions = [
        obj["x_opencti_description"]
        for obj in connector.stix_objects
        if obj.get("type") == "ipv4-addr"
    ]
    assert indicator_descriptions and all(
        "`unknown`" in description for description in indicator_descriptions
    )
    assert observable_descriptions and all(
        "`unknown`" in description for description in observable_descriptions
    )


def test_process_labels_without_classification(
    mock_opencti_connector_helper,  # noqa: ARG001
):
    """`_process_labels` must not raise and must label the IP as `unknown`."""
    connector, helper = _build_connector()
    connector._generate_greynoise_stix_identity()

    data = {
        "internet_scanner_intelligence": {
            "tags": [],
            "actor": "unknown",
            "bot": False,
            "tor": False,
            "vpn": False,
        },
        "business_service_intelligence": {"trust_level": "3", "name": "Acme"},
    }

    labels, malwares = connector._process_labels(data)

    assert labels and malwares == []
    label_values = [
        call.kwargs["value"]
        for call in helper.api.label.read_or_create_unchecked.call_args_list
    ]
    assert "gn-classification: unknown" in label_values


def test_threat_actor_without_classification(
    mock_opencti_connector_helper,  # noqa: ARG001
):
    """`_generate_stix_threat_actor_with_relationship` must not raise on a missing key."""
    connector, _ = _build_connector()
    connector._generate_greynoise_stix_identity()
    connector.stix_entity = {
        "id": "ipv4-addr--8ee5af46-71b6-4d6f-8f4a-3c3b9b6f2c11",
        "value": "203.0.113.10",
    }
    connector.first_seen = "2026-09-01T00:00:00Z"
    connector.last_seen = "2026-09-25T00:00:00Z"

    data = {"internet_scanner_intelligence": {"actor": "ExampleActor"}}

    connector._generate_stix_threat_actor_with_relationship(data)

    assert any(obj.get("type") == "threat-actor" for obj in connector.stix_objects)
