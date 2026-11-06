"""Host entity without HostName must be skipped instead of failing conversion."""

import pytest


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
