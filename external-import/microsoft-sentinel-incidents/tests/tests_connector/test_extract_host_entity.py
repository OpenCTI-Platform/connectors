"""Host entity without HostName must be skipped instead of failing conversion."""

import json
from unittest.mock import MagicMock

import pytest
from microsoft_sentinel_incidents_connector.connector import (
    MicrosoftSentinelIncidentsConnector,
)
from microsoft_sentinel_incidents_connector.converter_to_stix import ConverterToStix


@pytest.fixture
def connector():
    conn = object.__new__(MicrosoftSentinelIncidentsConnector)
    conn.helper = MagicMock()
    conn.client = MagicMock()
    conn.converter_to_stix = MagicMock()
    conn.config = MagicMock()
    conn.converter_to_stix.create_incident.return_value = MagicMock(id="incident--fake")
    conn.converter_to_stix.create_custom_case_incident.return_value = MagicMock()
    return conn


@pytest.fixture
def converter():
    conv = object.__new__(ConverterToStix)
    conv.helper = MagicMock()
    conv.tlp_marking = MagicMock(id="marking-definition--fake")
    conv.author = {"id": "identity--fake"}
    return conv


def _make_alert(entities):
    return {
        "Entities": json.dumps(entities),
        "Techniques": "[]",
        "SubTechniques": "[]",
    }


class TestExtractHostEntity:
    @pytest.mark.parametrize(
        "entity",
        [
            {"$id": "3", "Type": "host", "AzureID": "/subscriptions/x"},
            {"$id": "3", "Type": "host", "HostName": None},
            {"$id": "3", "Type": "host", "HostName": ""},
        ],
    )
    def test_host_entity_without_hostname_is_skipped(self, connector, entity):
        connector.client.get_alerts.return_value = [_make_alert([entity])]

        result = connector._extract_intelligence(0, {"AlertIds": "123"})

        connector.converter_to_stix.create_evidence_identity_system.assert_not_called()
        connector.converter_to_stix.create_evidence_custom_observable_hostname.assert_not_called()
        connector.helper.connector_logger.warning.assert_called_once_with(
            "Host entity without HostName, skipping", meta={"entity_id": "3"}
        )
        # Only incident + case
        assert len(result) == 2

    def test_host_entity_with_hostname_is_converted(self, connector):
        entity = {"$id": "3", "Type": "host", "HostName": "srv01"}
        connector.client.get_alerts.return_value = [_make_alert([entity])]

        connector._extract_intelligence(0, {"AlertIds": "123"})

        connector.converter_to_stix.create_evidence_identity_system.assert_called_once_with(
            entity
        )
        connector.converter_to_stix.create_evidence_custom_observable_hostname.assert_called_once_with(
            entity
        )


class TestConverterHostEntity:
    def test_custom_observable_hostname_without_hostname_returns_none(self, converter):
        assert (
            converter.create_evidence_custom_observable_hostname({"Type": "host"})
            is None
        )
        converter.helper.connector_logger.error.assert_not_called()

    def test_identity_system_without_hostname_returns_none(self, converter):
        assert converter.create_evidence_identity_system({"Type": "host"}) is None
        converter.helper.connector_logger.error.assert_not_called()
