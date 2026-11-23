"""Host entity without HostName must be skipped instead of failing conversion."""

from unittest.mock import MagicMock

import pytest
import stix2
from microsoft_sentinel_incidents_connector.converter_to_stix import ConverterToStix
from pycti import Identity


class TestExtractHostEntity:
    @pytest.mark.parametrize(
        "entity",
        [
            {"$id": "3", "Type": "host", "AzureID": "/subscriptions/x"},
            {"$id": "3", "Type": "host", "HostName": None},
            {"$id": "3", "Type": "host", "HostName": ""},
        ],
    )
    def test_host_entity_without_hostname_is_skipped(
        self, connector, make_alert, entity
    ):
        connector.client.get_alerts.return_value = [make_alert([entity])]

        result = connector._extract_intelligence(0, {"AlertIds": "123"})

        connector.converter_to_stix.create_evidence_identity_system.assert_not_called()
        connector.converter_to_stix.create_evidence_custom_observable_hostname.assert_not_called()
        connector.helper.connector_logger.warning.assert_called_once_with(
            "Host entity without HostName, skipping", meta={"entity_id": "3"}
        )
        # Only incident + case
        assert len(result) == 2

    def test_host_entity_with_hostname_is_converted(self, connector, make_alert):
        entity = {"$id": "3", "Type": "host", "HostName": "srv01"}
        connector.client.get_alerts.return_value = [make_alert([entity])]

        connector._extract_intelligence(0, {"AlertIds": "123"})

        connector.converter_to_stix.create_evidence_identity_system.assert_called_once_with(
            entity
        )
        connector.converter_to_stix.create_evidence_custom_observable_hostname.assert_called_once_with(
            entity
        )


class TestConvertHostEntity:
    def test_identity_system_uses_hostname(self):
        converter = object.__new__(ConverterToStix)
        converter.helper = MagicMock()
        converter.tlp_marking = stix2.TLP_GREEN
        converter.author = {"id": "identity--4f347cc9-0658-59ee-9707-134f434f9d1c"}

        identity = converter.create_evidence_identity_system(
            {"Type": "host", "HostName": "srv01"}
        )

        assert identity.name == "srv01"
        assert identity.identity_class == "system"
        assert identity.id == Identity.generate_id(
            name="srv01", identity_class="system"
        )
