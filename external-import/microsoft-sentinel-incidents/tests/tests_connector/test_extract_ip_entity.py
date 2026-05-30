"""Regression tests for #6183: ip entity without Address field must not crash."""

import json
from unittest.mock import MagicMock

import pytest
from microsoft_sentinel_incidents_connector.connector import (
    MicrosoftSentinelIncidentsConnector,
    detect_ip_version,
)


@pytest.fixture
def connector():
    conn = object.__new__(MicrosoftSentinelIncidentsConnector)
    conn.helper = MagicMock()
    conn.client = MagicMock()
    conn.converter_to_stix = MagicMock()
    conn.config = MagicMock()
    return conn


def _make_alert(entities):
    return {
        "Entities": json.dumps(entities),
        "Techniques": "[]",
        "SubTechniques": "[]",
    }


class TestDetectIpVersion:
    def test_ipv4(self):
        assert detect_ip_version("192.168.1.1") == "ipv4"

    def test_ipv4_cidr(self):
        assert detect_ip_version("10.0.0.0/8") == "ipv4"

    def test_ipv6(self):
        assert detect_ip_version("2001:db8::1") == "ipv6"


class TestExtractIpEntityWithoutAddress:
    """Cover lines 188-191: ip entity with missing Address is skipped."""

    def test_ip_entity_without_address_is_skipped(self, connector):
        """An ip entity with no Address field must be silently skipped (#6183)."""
        alert = _make_alert([{"Type": "ip"}])
        connector.client.get_alerts.return_value = [alert]
        connector.converter_to_stix.create_incident.return_value = MagicMock(
            id="incident--fake"
        )
        connector.converter_to_stix.create_custom_case_incident.return_value = (
            MagicMock()
        )

        result = connector._extract_intelligence(0, {"AlertIds": "123"})

        connector.converter_to_stix.create_evidence_ipv4.assert_not_called()
        connector.converter_to_stix.create_evidence_ipv6.assert_not_called()
        # Only incident + case, no IP objects
        assert len(result) == 2

    def test_ip_entity_with_none_address_is_skipped(self, connector):
        """An ip entity with Address explicitly set to None must be skipped."""
        alert = _make_alert([{"Type": "ip", "Address": None}])
        connector.client.get_alerts.return_value = [alert]
        connector.converter_to_stix.create_incident.return_value = MagicMock(
            id="incident--fake"
        )
        connector.converter_to_stix.create_custom_case_incident.return_value = (
            MagicMock()
        )

        connector._extract_intelligence(0, {"AlertIds": "123"})

        connector.converter_to_stix.create_evidence_ipv4.assert_not_called()
        connector.converter_to_stix.create_evidence_ipv6.assert_not_called()

    def test_ip_entity_with_valid_ipv4_address(self, connector):
        """An ip entity with a valid IPv4 address must call create_evidence_ipv4."""
        alert = _make_alert([{"Type": "ip", "Address": "10.0.0.1"}])
        connector.client.get_alerts.return_value = [alert]
        connector.converter_to_stix.create_incident.return_value = MagicMock(
            id="incident--fake"
        )
        connector.converter_to_stix.create_evidence_ipv4.return_value = MagicMock(
            id="ipv4-addr--fake"
        )
        connector.converter_to_stix.create_custom_case_incident.return_value = (
            MagicMock()
        )

        connector._extract_intelligence(0, {"AlertIds": "123"})

        connector.converter_to_stix.create_evidence_ipv4.assert_called_once_with(
            {"Type": "ip", "Address": "10.0.0.1"}
        )
        connector.converter_to_stix.create_evidence_ipv6.assert_not_called()

    def test_ip_entity_with_valid_ipv6_address(self, connector):
        """An ip entity with an IPv6 address must call create_evidence_ipv6."""
        alert = _make_alert([{"Type": "ip", "Address": "2001:db8::1"}])
        connector.client.get_alerts.return_value = [alert]
        connector.converter_to_stix.create_incident.return_value = MagicMock(
            id="incident--fake"
        )
        connector.converter_to_stix.create_evidence_ipv6.return_value = MagicMock(
            id="ipv6-addr--fake"
        )
        connector.converter_to_stix.create_custom_case_incident.return_value = (
            MagicMock()
        )

        connector._extract_intelligence(0, {"AlertIds": "123"})

        connector.converter_to_stix.create_evidence_ipv6.assert_called_once_with(
            {"Type": "ip", "Address": "2001:db8::1"}
        )
        connector.converter_to_stix.create_evidence_ipv4.assert_not_called()
