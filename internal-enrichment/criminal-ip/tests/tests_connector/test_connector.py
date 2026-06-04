from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, CriminalIPConnector

IPV4_STIX_ID = "ipv4-addr--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
DOMAIN_STIX_ID = "domain-name--b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"
EMAIL_STIX_ID = "email-addr--c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f"


def _make_settings(overrides: dict = None):
    """Helper to create a FakeConnectorSettings instance."""
    settings_dict = {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
            "name": "Criminal IP",
            "scope": "IPv4-Addr, Domain-Name",
            "log_level": "error",
            "auto": True,
        },
        "criminal_ip": {
            "token": "my-secret-api-key",
            "max_tlp": "TLP:AMBER",
        },
    }
    if overrides:
        for key, value in overrides.items():
            if key in settings_dict:
                settings_dict[key].update(value)
            else:
                settings_dict[key] = value

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


class TestCriminalIPConnector:
    """Tests for the CriminalIPConnector class."""

    def setup_method(self):
        self.settings = _make_settings()
        self.helper = MagicMock()
        self.helper.connect_scope = "IPv4-Addr, Domain-Name"
        self.helper.connector_logger = MagicMock()
        self.helper.check_max_tlp.return_value = True

    def test_connector_initialization(self):
        """Test connector initializes with correct attributes."""
        connector = CriminalIPConnector(config=self.settings, helper=self.helper)
        assert connector.token == "my-secret-api-key"
        assert connector.max_tlp == "TLP:AMBER"
        assert connector.client is not None

    def test_entity_in_scope_ipv4(self):
        """Test that ipv4-addr entities are in scope."""
        connector = CriminalIPConnector(config=self.settings, helper=self.helper)
        data = {"entity_id": IPV4_STIX_ID}
        assert connector.entity_in_scope(data) is True

    def test_entity_in_scope_domain(self):
        """Test that domain-name entities are in scope."""
        connector = CriminalIPConnector(config=self.settings, helper=self.helper)
        data = {"entity_id": DOMAIN_STIX_ID}
        assert connector.entity_in_scope(data) is True

    def test_entity_not_in_scope(self):
        """Test that unsupported entity types are out of scope."""
        connector = CriminalIPConnector(config=self.settings, helper=self.helper)
        data = {"entity_id": EMAIL_STIX_ID}
        assert connector.entity_in_scope(data) is False

    def test_extract_and_check_markings_valid(self):
        """Test that valid TLP markings pass validation."""
        connector = CriminalIPConnector(config=self.settings, helper=self.helper)
        entity = {
            "objectMarking": [{"definition_type": "TLP", "definition": "TLP:GREEN"}]
        }
        # Should not raise
        connector._extract_and_check_markings(entity)
        self.helper.check_max_tlp.assert_called_once_with("TLP:GREEN", "TLP:AMBER")

    def test_extract_and_check_markings_no_markings(self):
        """Test default TLP:CLEAR when no markings present."""
        connector = CriminalIPConnector(config=self.settings, helper=self.helper)
        entity = {"objectMarking": []}
        connector._extract_and_check_markings(entity)
        self.helper.check_max_tlp.assert_called_once_with("TLP:CLEAR", "TLP:AMBER")

    def test_extract_and_check_markings_exceeds_max_tlp(self):
        """Test raises ValueError when TLP exceeds max."""
        self.helper.check_max_tlp.return_value = False
        connector = CriminalIPConnector(config=self.settings, helper=self.helper)
        entity = {
            "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED"}]
        }
        with pytest.raises(ValueError, match="Do not send any data"):
            connector._extract_and_check_markings(entity)

    def test_process_message_unsupported_type(self):
        """Test process_message handles unsupported observable type gracefully."""
        connector = CriminalIPConnector(config=self.settings, helper=self.helper)
        self.helper.stix2_create_bundle.return_value = "{}"
        self.helper.send_stix2_bundle.return_value = ["bundle-1"]

        data = {
            "entity_id": IPV4_STIX_ID,
            "enrichment_entity": {"entity_type": "IPv4-Addr", "objectMarking": []},
            "stix_objects": [{"type": "ipv4-addr", "id": IPV4_STIX_ID}],
            "stix_entity": {
                "id": IPV4_STIX_ID,
                "value": "1.2.3.4",
                "type": "unknown-type",
            },
        }
        # Should handle gracefully (sends back original bundle)
        connector.process_message(data)
        self.helper.send_stix2_bundle.assert_called()

    def test_process_message_out_of_scope_with_event_type(self):
        """Test that out-of-scope entity with event_type raises ValueError."""
        self.helper.connect_scope = "IPv4-Addr"
        connector = CriminalIPConnector(config=self.settings, helper=self.helper)
        self.helper.stix2_create_bundle.return_value = "{}"
        self.helper.send_stix2_bundle.return_value = ["bundle-1"]

        data = {
            "entity_id": EMAIL_STIX_ID,
            "enrichment_entity": {"entity_type": "Email-Addr", "objectMarking": []},
            "stix_objects": [{"type": "email-addr", "id": EMAIL_STIX_ID}],
            "stix_entity": {
                "id": EMAIL_STIX_ID,
                "value": "test@test.com",
                "type": "email-addr",
            },
            "event_type": "create",
        }
        # Out of scope with event_type -> sends back original bundle on error
        connector.process_message(data)
        self.helper.send_stix2_bundle.assert_called()

    def test_process_message_out_of_scope_no_event_type(self):
        """Test that out-of-scope entity without event_type sends original bundle."""
        self.helper.connect_scope = "IPv4-Addr"
        connector = CriminalIPConnector(config=self.settings, helper=self.helper)
        self.helper.stix2_create_bundle.return_value = "{}"
        self.helper.send_stix2_bundle.return_value = ["bundle-1"]

        data = {
            "entity_id": EMAIL_STIX_ID,
            "enrichment_entity": {"entity_type": "Email-Addr", "objectMarking": []},
            "stix_objects": [{"type": "email-addr", "id": EMAIL_STIX_ID}],
            "stix_entity": {
                "id": EMAIL_STIX_ID,
                "value": "test@test.com",
                "type": "email-addr",
            },
        }
        connector.process_message(data)
        self.helper.send_stix2_bundle.assert_called()
