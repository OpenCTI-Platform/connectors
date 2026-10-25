"""Unit tests for the DECTRAX OpenCTI External Import Connector."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
import stix2
from pycti import (

    Identity,
    Indicator,
    MarkingDefinition,
    StixCoreRelationship,
)

from src.main import (
    DectraxConnector,
    resolve_tlp_marking,

    validate_ipv4_address,
)


class MockConnectorHelper:
    """Mock OpenCTIConnectorHelper for isolated unit testing."""

    def __init__(self, state: Optional[Dict[str, Any]] = None) -> None:
        self.state = state or {}
        self.connect_name = "DECTRAX Autonomous Deception"
        self.connect_id = "test-dectrax-id"
        self.connector_logger = logging.getLogger("MockConnectorHelper")
        self.bundles_sent: List[Any] = []
        self.scheduled = False
        self.schedule_callback = None
        self.duration_period = None
        self.api = MagicMock()
        self.api.work.initiate_work.return_value = "work-1234"

    def get_state(self) -> Dict[str, Any]:
        return dict(self.state)

    def set_state(self, new_state: Dict[str, Any]) -> None:
        self.state = dict(new_state)

    def stix2_create_bundle(self, objects: List[Any]) -> stix2.Bundle:
        return stix2.Bundle(objects=objects, allow_custom=True)

    def send_stix2_bundle(
        self,
        bundle: stix2.Bundle,
        work_id: Optional[str] = None,
        cleanup_inconsistent_bundle: bool = True,
    ) -> List[str]:
        self.bundles_sent.append(bundle)
        return ["bundle-result-id-1"]

    def schedule_iso(self, message_callback: Any, duration_period: str) -> None:
        self.scheduled = True
        self.schedule_callback = message_callback
        self.duration_period = duration_period


def _base_config(**overrides: Any) -> Dict[str, Any]:
    cfg = {
        "dectrax": {
            "api_url": "http://127.0.0.1:8000",
            "api_key": "test-key",
            "edl_endpoint": "/api/v1/edl/firewall.txt",
            "telemetry_endpoint": "/api/v1/telemetry/threats",
            "tlp_level": "clear",
            "create_indicators": True,
            "create_observables": True,
            "sync_modbus": True,
            "sync_ldap": True,
            "sync_rdp": True,
        },
        "connector": {
            "duration_period": "PT1H",
        },
    }
    if overrides:
        for k, v in overrides.items():
            if k in cfg["dectrax"]:
                cfg["dectrax"][k] = v
            else:
                cfg[k] = v
    return cfg


# ==============================================================================
# Issue 1: TLP Mapping & Fail-Open Prevention
# ==============================================================================

class TestTLPHandling:
    """Verify strict TLP validation and custom statement markings."""

    def test_standard_markings(self) -> None:
        assert resolve_tlp_marking("white") == stix2.TLP_WHITE
        assert resolve_tlp_marking("green") == stix2.TLP_GREEN
        assert resolve_tlp_marking("amber") == stix2.TLP_AMBER
        assert resolve_tlp_marking("red") == stix2.TLP_RED

    def test_clear_and_amber_strict_statement_markings(self) -> None:
        clear = resolve_tlp_marking("clear")
        assert clear.id == MarkingDefinition.generate_id("TLP", "TLP:CLEAR")
        assert getattr(clear, "x_opencti_definition", None) == "TLP:CLEAR"

        amber_strict = resolve_tlp_marking("amber+strict")
        assert amber_strict.id == MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT")
        assert getattr(amber_strict, "x_opencti_definition", None) == "TLP:AMBER+STRICT"

    @pytest.mark.parametrize("invalid_tlp", ["invalid", "blue", "confidential", "", "none"])
    def test_rejects_unsupported_tlp(self, invalid_tlp: str) -> None:
        with pytest.raises(ValueError, match="Unsupported TLP marking"):
            resolve_tlp_marking(invalid_tlp)

    def test_connector_startup_rejects_invalid_tlp(self) -> None:
        cfg = _base_config(tlp_level="super-secret")
        helper = MockConnectorHelper()
        with pytest.raises(ValueError, match="Unsupported DECTRAX_TLP_LEVEL"):
            DectraxConnector(config=cfg, helper=helper)


# ==============================================================================
# Issue 2: Empty Feed Stays Empty (No Synthetic Fallbacks)
# ==============================================================================

class TestEmptyFeed:
    """Verify that empty telemetry returns empty list and no synthetic records."""

    @patch("requests.get")
    def test_collect_empty_feed_returns_empty_list(self, mock_get: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_resp.text = ""
        mock_get.return_value = mock_resp

        connector = DectraxConnector(config=_base_config(), helper=MockConnectorHelper())
        records = connector.collect()
        assert records == []
        assert len(records) == 0

    def test_transform_empty_feed_returns_empty_list(self) -> None:
        connector = DectraxConnector(config=_base_config(), helper=MockConnectorHelper())
        objects = connector.transform([])
        assert objects == []


# ==============================================================================
# Issue 3: Strict IPv4 Validation
# ==============================================================================

class TestIPv4Validation:
    """Verify strict IPv4 validation and rejection of IPv6/malformed IPs."""

    @pytest.mark.parametrize("valid_ip", ["198.51.100.45", "10.0.0.1", "203.0.113.88", "1.1.1.1"])
    def test_accepts_valid_ipv4(self, valid_ip: str) -> None:
        assert validate_ipv4_address(valid_ip) is True

    @pytest.mark.parametrize("ipv6", ["2001:db8::1", "::1", "fe80::1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"])
    def test_rejects_ipv6(self, ipv6: str) -> None:
        assert validate_ipv4_address(ipv6) is False

    @pytest.mark.parametrize("malformed", ["256.0.0.1", "1.2.3", "not-an-ip", "10.0.0.1/24", "", None, 12345])
    def test_rejects_malformed(self, malformed: Any) -> None:
        assert validate_ipv4_address(malformed) is False

    def test_transform_skips_ipv6_and_malformed(self) -> None:
        connector = DectraxConnector(config=_base_config(), helper=MockConnectorHelper())
        telemetry = [
            {"attacker_ip": "2001:db8::1", "decoy_service": "RDP"},
            {"attacker_ip": "invalid-ip", "decoy_service": "SSH"},
            {"attacker_ip": "198.51.100.5", "decoy_service": "RDP"},
        ]
        objects = connector.transform(telemetry)
        observables = [obj for obj in objects if isinstance(obj, stix2.IPv4Address)]
        assert len(observables) == 1
        assert observables[0].value == "198.51.100.5"


# ==============================================================================
# Issue 7: Protocol Flag Filtering
# ==============================================================================

class TestProtocolFlags:
    """Verify sync_rdp, sync_ldap, sync_modbus config flags are enforced."""

    def test_protocol_filtering_disabled(self) -> None:
        cfg = _base_config(sync_rdp=False, sync_ldap=False, sync_modbus=False)
        connector = DectraxConnector(config=cfg, helper=MockConnectorHelper())

        telemetry = [
            {"attacker_ip": "198.51.100.1", "decoy_service": "RDP", "dest_port": 3389},
            {"attacker_ip": "198.51.100.2", "decoy_service": "LDAP", "dest_port": 389},
            {"attacker_ip": "198.51.100.3", "decoy_service": "MODBUS", "dest_port": 502},
            {"attacker_ip": "198.51.100.4", "decoy_service": "SSH", "dest_port": 22},
        ]

        objects = connector.transform(telemetry)
        indicators = [obj for obj in objects if isinstance(obj, stix2.Indicator)]
        # RDP, LDAP, MODBUS filtered out; only SSH should remain
        assert len(indicators) == 1
        assert "198.51.100.4" in indicators[0].pattern

    def test_protocol_filtering_enabled(self) -> None:
        cfg = _base_config(sync_rdp=True, sync_ldap=True, sync_modbus=True)
        connector = DectraxConnector(config=cfg, helper=MockConnectorHelper())

        telemetry = [
            {"attacker_ip": "198.51.100.1", "decoy_service": "RDP", "dest_port": 3389},
            {"attacker_ip": "198.51.100.2", "decoy_service": "LDAP", "dest_port": 389},
            {"attacker_ip": "198.51.100.3", "decoy_service": "MODBUS", "dest_port": 502},
        ]

        objects = connector.transform(telemetry)
        indicators = [obj for obj in objects if isinstance(obj, stix2.Indicator)]
        assert len(indicators) == 3


# ==============================================================================
# Issue 8: Deterministic STIX IDs
# ==============================================================================

class TestDeterministicSTIXIDs:
    """Verify STIX objects use deterministic pycti helper IDs."""

    def test_deterministic_ids_consistency(self) -> None:
        helper = MockConnectorHelper()
        connector1 = DectraxConnector(config=_base_config(), helper=helper)
        connector2 = DectraxConnector(config=_base_config(), helper=helper)

        # 1. Identity ID deterministic
        expected_identity_id = Identity.generate_id(
            "DECTRAX Autonomous Deception Platform", "organization"
        )
        assert connector1.identity.id == expected_identity_id
        assert connector2.identity.id == expected_identity_id

        # 2. Indicator & Relationship IDs deterministic
        telemetry = [
            {
                "attacker_ip": "198.51.100.50",
                "decoy_service": "RDP",
                "dest_port": 3389,
                "first_seen": "2026-10-22T00:00:00+00:00",
                "techniques": ["T1021.001"],
            }
        ]

        objects1 = connector1.transform(telemetry)
        objects2 = connector2.transform(telemetry)

        ind1 = next(obj for obj in objects1 if isinstance(obj, stix2.Indicator))
        ind2 = next(obj for obj in objects2 if isinstance(obj, stix2.Indicator))
        expected_ind_id = Indicator.generate_id("[ipv4-addr:value = '198.51.100.50']")
        assert ind1.id == expected_ind_id
        assert ind1.id == ind2.id

        rel1 = next(obj for obj in objects1 if isinstance(obj, stix2.Relationship) and obj.relationship_type == "related-to")
        rel2 = next(obj for obj in objects2 if isinstance(obj, stix2.Relationship) and obj.relationship_type == "related-to")
        expected_rel_id = StixCoreRelationship.generate_id("related-to", ind1.id, connector1.identity.id)
        assert rel1.id == expected_rel_id
        assert rel1.id == rel2.id


# ==============================================================================
# Issue 9 & 10: Lifecycle & State Persistence Merge
# ==============================================================================

class TestLifecycleAndStatePersistence:
    """Verify lifecycle execution and state merging without key overwriting."""

    @patch("requests.get")
    def test_process_message_merges_state(self, mock_get: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"attacker_ip": "198.51.100.77", "decoy_service": "RDP", "dest_port": 3389}
        ]
        mock_resp.text = ""
        mock_get.return_value = mock_resp

        initial_state = {
            "initial_key": "preserved_val",
            "last_sync": "2026-10-21T12:00:00+00:00",
            "records_imported": 5,
        }
        helper = MockConnectorHelper(state=initial_state)
        connector = DectraxConnector(config=_base_config(), helper=helper)

        connector.process_message()

        final_state = helper.get_state()
        # Ensure previous keys were not wiped
        assert final_state["initial_key"] == "preserved_val"
        # Ensure updated keys exist and are merged
        assert "last_run" in final_state
        assert "last_sync" in final_state
        assert final_state["records_imported"] == 1
        assert len(helper.bundles_sent) == 1

    def test_schedule_iso_called_on_run(self) -> None:
        helper = MockConnectorHelper()
        connector = DectraxConnector(config=_base_config(), helper=helper)
        connector.run()
        assert helper.scheduled is True
        assert helper.duration_period == "PT1H"
        assert helper.schedule_callback == connector.process_message
