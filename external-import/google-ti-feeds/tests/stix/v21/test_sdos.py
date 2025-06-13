"""Module to test the STIX 2.1 SDO (STIX Domain Objects) models."""

from datetime import datetime, timezone
from typing import Any, Dict

import pytest
from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.stix.v21.models.ovs.attack_motivation_ov_enums import (
    AttackMotivationOV,
)
from connector.src.stix.v21.models.ovs.attack_resource_level_ov_enums import (
    AttackResourceLevelOV,
)
from connector.src.stix.v21.models.ovs.grouping_context_ov_enums import (
    GroupingContextOV,
)
from connector.src.stix.v21.models.ovs.identity_class_ov_enums import IdentityClassOV
from connector.src.stix.v21.models.ovs.indicator_type_ov_enums import IndicatorTypeOV
from connector.src.stix.v21.models.ovs.industry_sector_ov_enums import IndustrySectorOV
from connector.src.stix.v21.models.ovs.infrastructure_type_ov_enums import (
    InfrastructureTypeOV,
)
from connector.src.stix.v21.models.ovs.malware_type_ov_enums import MalwareTypeOV
from connector.src.stix.v21.models.ovs.report_type_ov_enums import ReportTypeOV
from connector.src.stix.v21.models.sdos.attack_pattern_model import AttackPatternModel
from connector.src.stix.v21.models.sdos.grouping_model import GroupingModel
from connector.src.stix.v21.models.sdos.identity_model import IdentityModel
from connector.src.stix.v21.models.sdos.indicator_model import IndicatorModel
from connector.src.stix.v21.models.sdos.infrastructure_model import InfrastructureModel
from connector.src.stix.v21.models.sdos.intrusion_set_model import IntrusionSetModel
from connector.src.stix.v21.models.sdos.malware_model import MalwareModel
from connector.src.stix.v21.models.sdos.report_model import ReportModel
from stix2 import AttackPattern, Identity, Indicator

# =====================
# Fixtures
# =====================


@pytest.fixture
def now() -> datetime:
    """Fix timestamp for deterministic test results."""
    return datetime.now(timezone.utc)


@pytest.fixture
def common_sdo_fields(now: datetime) -> Dict[str, Any]:
    """Create Common fields for all SDO objects."""
    return {
        "spec_version": "2.1",
        "created": now,
        "modified": now,
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "revoked": False,
        "labels": ["malicious-activity"],
        "confidence": 85,
        "lang": "en",
        "object_marking_refs": [
            "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
        ],
    }


@pytest.fixture
def kill_chain_phase_data() -> Dict[str, str]:
    """Create Data for a kill chain phase."""
    return {
        "kill_chain_name": "mitre-attack",
        "phase_name": "initial-access",
    }


# =====================
# Test Cases
# =====================

# Scenario: Testing AttackPattern model


def test_attack_pattern_basic_creation(common_sdo_fields: Dict[str, Any]):
    """Test that an AttackPattern model can be created with basic fields."""
    # Given: Minimal required data for an Attack Pattern
    data = {
        **common_sdo_fields,
        "type": "attack-pattern",
        "name": "Phishing",
    }

    # When: Creating an AttackPatternModel
    attack_pattern = AttackPatternModel(**data)

    # Then: The model should have the expected values
    assert attack_pattern.type == "attack-pattern"  # noqa: S101
    assert attack_pattern.name == "Phishing"  # noqa: S101
    assert attack_pattern.id.startswith("attack-pattern--")  # noqa: S101


def test_attack_pattern_full_creation(
    common_sdo_fields: Dict[str, Any], kill_chain_phase_data: Dict[str, str]
):
    """Test that an AttackPattern model can be created with all fields."""
    # Given: Complete data for an Attack Pattern
    data = {
        **common_sdo_fields,
        "type": "attack-pattern",
        "name": "Phishing",
        "description": "Phishing is a technique used by threat actors to...",
        "aliases": ["Email Phishing", "Spear Phishing"],
        "kill_chain_phases": [
            kill_phase := KillChainPhaseModel(**kill_chain_phase_data)
        ],
        "custom_properties": {"x_mitre_id": "T1566"},
    }

    # When: Creating an AttackPatternModel
    attack_pattern = AttackPatternModel(**data)

    # Then: The model should have the expected values
    assert attack_pattern.name == "Phishing"  # noqa: S101
    assert attack_pattern.description.startswith(  # noqa: S101
        "Phishing is a technique"
    )
    assert "Email Phishing" in attack_pattern.aliases  # noqa: S101
    assert attack_pattern.kill_chain_phases[0] == kill_phase  # noqa: S101
    assert attack_pattern.custom_properties["x_mitre_id"] == "T1566"  # noqa: S101

    # And: The ID should be generated based on name and x_mitre_id
    assert attack_pattern.id.startswith("attack-pattern--")  # noqa: S101


def test_attack_pattern_to_stix_object(common_sdo_fields: Dict[str, Any]):
    """Test conversion of AttackPatternModel to a STIX object."""
    # Given: An AttackPatternModel
    attack_pattern = AttackPatternModel(
        **{
            **common_sdo_fields,
            "type": "attack-pattern",
            "name": "Phishing",
            "description": "Phishing attacks...",
            "custom_properties": {"x_mitre_id": "T1566"},
        }
    )

    # When: Converting to a STIX object
    stix_obj = attack_pattern.to_stix2_object()

    # Then: The result should be a proper STIX AttackPattern
    assert isinstance(stix_obj, AttackPattern)  # noqa: S101
    assert stix_obj.name == "Phishing"  # noqa: S101
    assert stix_obj.description == "Phishing attacks..."  # noqa: S101


# Scenario: Testing Identity model


def test_identity_basic_creation(common_sdo_fields: Dict[str, Any]):
    """Test that an Identity model can be created with basic fields."""
    # Given: Minimal required data for an Identity
    data = {
        **common_sdo_fields,
        "type": "identity",
        "name": "ACME Cybersecurity",
        "identity_class": IdentityClassOV.ORGANIZATION,
    }

    # When: Creating an IdentityModel
    identity = IdentityModel(**data)

    # Then: The model should have the expected values
    assert identity.type == "identity"  # noqa: S101
    assert identity.name == "ACME Cybersecurity"  # noqa: S101
    assert identity.identity_class == IdentityClassOV.ORGANIZATION  # noqa: S101
    assert identity.id.startswith("identity--")  # noqa: S101


def test_identity_full_creation(common_sdo_fields: Dict[str, Any]):
    """Test that an Identity model can be created with all fields."""
    # Given: Complete data for an Identity
    data = {
        **common_sdo_fields,
        "type": "identity",
        "name": "ACME Cybersecurity",
        "description": "A cybersecurity firm specializing in threat intelligence",
        "roles": ["intelligence-provider", "security-vendor"],
        "identity_class": IdentityClassOV.ORGANIZATION,
        "sectors": [IndustrySectorOV.TECHNOLOGY],
        "contact_information": "contact@acme-cyber.com",
    }

    # When: Creating an IdentityModel
    identity = IdentityModel(**data)

    # Then: The model should have the expected values
    assert identity.name == "ACME Cybersecurity"  # noqa: S101
    assert identity.description.startswith("A cybersecurity firm")  # noqa: S101
    assert "intelligence-provider" in identity.roles  # noqa: S101
    assert identity.sectors[0] == IndustrySectorOV.TECHNOLOGY  # noqa: S101
    assert identity.contact_information == "contact@acme-cyber.com"  # noqa: S101


def test_identity_to_stix_object(common_sdo_fields: Dict[str, Any]):
    """Test conversion of IdentityModel to a STIX object."""
    # Given: An IdentityModel
    identity = IdentityModel(
        **{
            **common_sdo_fields,
            "type": "identity",
            "name": "ACME Cybersecurity",
            "identity_class": IdentityClassOV.ORGANIZATION,
        }
    )

    # When: Converting to a STIX object
    stix_obj = identity.to_stix2_object()

    # Then: The result should be a proper STIX Identity
    assert isinstance(stix_obj, Identity)  # noqa: S101
    assert stix_obj.name == "ACME Cybersecurity"  # noqa: S101
    assert stix_obj.identity_class == "organization"  # noqa: S101


# Scenario: Testing Indicator model


def test_indicator_basic_creation(common_sdo_fields: Dict[str, Any], now: datetime):
    """Test that an Indicator model can be created with basic fields."""
    # Given: Minimal required data for an Indicator
    data = {
        **common_sdo_fields,
        "type": "indicator",
        "indicator_types": [IndicatorTypeOV.MALICIOUS_ACTIVITY],
        "pattern": "[file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4']",
        "pattern_type": "stix",
        "valid_from": now,
    }

    # When: Creating an IndicatorModel
    indicator = IndicatorModel(**data)

    # Then: The model should have the expected values
    assert indicator.type == "indicator"  # noqa: S101
    assert indicator.pattern_type == "stix"  # noqa: S101
    assert indicator.id.startswith("indicator--")  # noqa: S101
    assert IndicatorTypeOV.MALICIOUS_ACTIVITY in indicator.indicator_types  # noqa: S101


def test_indicator_full_creation(
    common_sdo_fields: Dict[str, Any],
    now: datetime,
    kill_chain_phase_data: Dict[str, str],
):
    """Test that an Indicator model can be created with all fields."""
    # Given: Complete data for an Indicator
    data = {
        **common_sdo_fields,
        "type": "indicator",
        "name": "Malicious File Indicator",
        "description": "Indicator for a known malicious file",
        "indicator_types": [IndicatorTypeOV.MALICIOUS_ACTIVITY],
        "pattern": "[file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": now,
        "valid_until": datetime(now.year + 1, now.month, now.day, tzinfo=timezone.utc),
        "kill_chain_phases": [KillChainPhaseModel(**kill_chain_phase_data)],
    }

    # When: Creating an IndicatorModel
    indicator = IndicatorModel(**data)

    # Then: The model should have the expected values
    assert indicator.name == "Malicious File Indicator"  # noqa: S101
    assert indicator.description.startswith("Indicator for a")  # noqa: S101
    assert indicator.pattern.startswith("[file:hashes.MD5")  # noqa: S101
    assert indicator.valid_from == now  # noqa: S101
    assert indicator.valid_until > now  # noqa: S101
    assert indicator.kill_chain_phases[0].phase_name == "initial-access"  # noqa: S101


def test_indicator_to_stix_object(common_sdo_fields: Dict[str, Any], now: datetime):
    """Test conversion of IndicatorModel to a STIX object."""
    # Given: An IndicatorModel
    indicator = IndicatorModel(
        **{
            **common_sdo_fields,
            "type": "indicator",
            "indicator_types": [IndicatorTypeOV.MALICIOUS_ACTIVITY],
            "pattern": "[file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4']",
            "pattern_type": "stix",
            "valid_from": now,
        }
    )

    # When: Converting to a STIX object
    stix_obj = indicator.to_stix2_object()

    # Then: The result should be a proper STIX Indicator
    assert isinstance(stix_obj, Indicator)  # noqa: S101
    assert (  # noqa: S101
        stix_obj.pattern == "[file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4']"
    )
    assert stix_obj.pattern_type == "stix"  # noqa: S101


# Scenario: Testing Malware model


def test_malware_basic_creation(common_sdo_fields: Dict[str, Any]):
    """Test that a Malware model can be created with basic fields."""
    # Given: Minimal required data for a Malware
    data = {
        **common_sdo_fields,
        "type": "malware",
        "name": "BlackCat",
        "malware_types": [MalwareTypeOV.RANSOMWARE],
        "is_family": True,
    }

    # When: Creating a MalwareModel
    malware = MalwareModel(**data)

    # Then: The model should have the expected values
    assert malware.type == "malware"  # noqa: S101
    assert malware.is_family is True  # noqa: S101
    assert malware.id.startswith("malware--")  # noqa: S101
    assert MalwareTypeOV.RANSOMWARE in malware.malware_types  # noqa: S101


def test_malware_full_creation(
    common_sdo_fields: Dict[str, Any],
    now: datetime,
    kill_chain_phase_data: Dict[str, str],
):
    """Test that a Malware model can be created with all fields."""
    # Given: Complete data for a Malware
    data = {
        **common_sdo_fields,
        "type": "malware",
        "name": "BlackCat",
        "description": "BlackCat (also known as ALPHV) is a ransomware...",
        "malware_types": [MalwareTypeOV.RANSOMWARE],
        "is_family": True,
        "aliases": ["ALPHV"],
        "kill_chain_phases": [KillChainPhaseModel(**kill_chain_phase_data)],
        "first_seen": now,
        "last_seen": now,
        "os_execution_envs": ["Windows"],
        "capabilities": ["anti-emulation", "degrades-security-software"],
    }

    # When: Creating a MalwareModel
    malware = MalwareModel(**data)

    # Then: The model should have the expected values
    assert malware.name == "BlackCat"  # noqa: S101
    assert malware.description.startswith("BlackCat")  # noqa: S101
    assert "ALPHV" in malware.aliases  # noqa: S101
    assert malware.first_seen == now  # noqa: S101
    assert malware.last_seen == now  # noqa: S101
    assert "Windows" in malware.os_execution_envs  # noqa: S101


# Scenario: Testing InfrastructureModel


def test_infrastructure_basic_creation(common_sdo_fields: Dict[str, Any]):
    """Test that an Infrastructure model can be created with basic fields."""
    # Given: Minimal required data for Infrastructure
    data = {
        **common_sdo_fields,
        "type": "infrastructure",
        "name": "C2 Server",
        "infrastructure_types": [InfrastructureTypeOV.COMMAND_AND_CONTROL],
    }

    # When: Creating an InfrastructureModel
    infrastructure = InfrastructureModel(**data)

    # Then: The model should have the expected values
    assert infrastructure.type == "infrastructure"  # noqa: S101
    assert infrastructure.name == "C2 Server"  # noqa: S101
    assert infrastructure.id.startswith("infrastructure--")  # noqa: S101
    assert (  # noqa: S101
        InfrastructureTypeOV.COMMAND_AND_CONTROL in infrastructure.infrastructure_types
    )


def test_infrastructure_full_creation(
    common_sdo_fields: Dict[str, Any],
    now: datetime,
    kill_chain_phase_data: Dict[str, str],
):
    """Test that an Infrastructure model can be created with all fields."""
    # Given: Complete data for Infrastructure
    data = {
        **common_sdo_fields,
        "type": "infrastructure",
        "name": "Botnet Command and Control",
        "description": "Infrastructure used for botnet command and control",
        "infrastructure_types": [
            InfrastructureTypeOV.COMMAND_AND_CONTROL,
            InfrastructureTypeOV.BOTNET,
        ],
        "aliases": ["MalBot C2", "BotnetXYZ Infrastructure"],
        "kill_chain_phases": [KillChainPhaseModel(**kill_chain_phase_data)],
        "first_seen": now,
        "last_seen": now,
    }

    # When: Creating an InfrastructureModel
    infrastructure = InfrastructureModel(**data)

    # Then: The model should have the expected values
    assert infrastructure.name == "Botnet Command and Control"  # noqa: S101
    assert infrastructure.description.startswith(  # noqa: S101
        "Infrastructure used for"
    )
    assert len(infrastructure.infrastructure_types) == 2  # noqa: S101
    assert "MalBot C2" in infrastructure.aliases  # noqa: S101
    assert infrastructure.first_seen == now  # noqa: S101
    assert infrastructure.last_seen == now  # noqa: S101


# Scenario: Testing IntrusionSetModel


def test_intrusion_set_basic_creation(common_sdo_fields: Dict[str, Any]):
    """Test that an IntrusionSet model can be created with basic fields."""
    # Given: Minimal required data for an IntrusionSet
    data = {
        **common_sdo_fields,
        "type": "intrusion-set",
        "name": "APT42",
    }

    # When: Creating an IntrusionSetModel
    intrusion_set = IntrusionSetModel(**data)

    # Then: The model should have the expected values
    assert intrusion_set.type == "intrusion-set"  # noqa: S101
    assert intrusion_set.name == "APT42"  # noqa: S101
    assert intrusion_set.id.startswith("intrusion-set--")  # noqa: S101


def test_intrusion_set_full_creation(common_sdo_fields: Dict[str, Any], now: datetime):
    """Test that an IntrusionSet model can be created with all fields."""
    # Given: Complete data for an IntrusionSet
    data = {
        **common_sdo_fields,
        "type": "intrusion-set",
        "name": "APT42",
        "description": "A sophisticated threat group targeting financial institutions",
        "aliases": ["FinancialGroup", "MoneyTakers"],
        "first_seen": now,
        "last_seen": now,
        "goals": ["financial-gain", "information-theft"],
        "resource_level": AttackResourceLevelOV.ORGANIZATION,
        "primary_motivation": AttackMotivationOV.PERSONAL_GAIN,
        "secondary_motivations": [AttackMotivationOV.ORGANIZATIONAL_GAIN],
    }

    # When: Creating an IntrusionSetModel
    intrusion_set = IntrusionSetModel(**data)

    # Then: The model should have the expected values
    assert intrusion_set.name == "APT42"  # noqa: S101
    assert intrusion_set.description.startswith("A sophisticated")  # noqa: S101
    assert "FinancialGroup" in intrusion_set.aliases  # noqa: S101
    assert "financial-gain" in intrusion_set.goals  # noqa: S101
    assert (  # noqa: S101
        intrusion_set.resource_level == AttackResourceLevelOV.ORGANIZATION
    )
    assert (  # noqa: S101
        intrusion_set.primary_motivation == AttackMotivationOV.PERSONAL_GAIN
    )


# Scenario: Testing ReportModel


def test_report_basic_creation(common_sdo_fields: Dict[str, Any], now: datetime):
    """Test that a Report model can be created with basic fields."""
    # Given: Minimal required data for a Report
    data = {
        **common_sdo_fields,
        "type": "report",
        "name": "APT42 Campaign Analysis",
        "report_types": [ReportTypeOV.THREAT_REPORT],
        "published": now,
        "object_refs": ["indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"],
    }

    # When: Creating a ReportModel
    report = ReportModel(**data)

    # Then: The model should have the expected values
    assert report.type == "report"  # noqa: S101
    assert report.name == "APT42 Campaign Analysis"  # noqa: S101
    assert report.id.startswith("report--")  # noqa: S101
    assert ReportTypeOV.THREAT_REPORT in report.report_types  # noqa: S101
    assert report.published == now  # noqa: S101
    assert len(report.object_refs) == 1  # noqa: S101


def test_report_full_creation(common_sdo_fields: Dict[str, Any], now: datetime):
    """Test that a Report model can be created with all fields."""
    # Given: Complete data for a Report
    data = {
        **common_sdo_fields,
        "type": "report",
        "name": "APT42 Campaign Analysis",
        "description": "A comprehensive analysis of the APT42 campaign from January 2023",
        "report_types": [ReportTypeOV.THREAT_REPORT, ReportTypeOV.ATTACK_PATTERN],
        "published": now,
        "object_refs": [
            "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
            "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
        ],
    }

    # When: Creating a ReportModel
    report = ReportModel(**data)

    # Then: The model should have the expected values
    assert report.name == "APT42 Campaign Analysis"  # noqa: S101
    assert report.description.startswith("A comprehensive analysis")  # noqa: S101
    assert len(report.report_types) == 2  # noqa: S101
    assert len(report.object_refs) == 3  # noqa: S101


# Scenario: Testing GroupingModel


def test_grouping_basic_creation(common_sdo_fields: Dict[str, Any]):
    """Test that a Grouping model can be created with basic fields."""
    # Given: Minimal required data for a Grouping
    data = {
        **common_sdo_fields,
        "type": "grouping",
        "name": "Suspicious Activity Group",
        "context": GroupingContextOV.SUSPICIOUS_ACTIVITY,
        "object_refs": ["indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"],
    }

    # When: Creating a GroupingModel
    grouping = GroupingModel(**data)

    # Then: The model should have the expected values
    assert grouping.type == "grouping"  # noqa: S101
    assert grouping.context == GroupingContextOV.SUSPICIOUS_ACTIVITY  # noqa: S101
    assert grouping.id.startswith("grouping--")  # noqa: S101
    assert len(grouping.object_refs) == 1  # noqa: S101


def test_grouping_full_creation(common_sdo_fields: Dict[str, Any]):
    """Test that a Grouping model can be created with all fields."""
    # Given: Complete data for a Grouping
    data = {
        **common_sdo_fields,
        "type": "grouping",
        "name": "Suspicious Activity Group",
        "description": "A collection of indicators related to a specific suspicious activity",
        "context": GroupingContextOV.SUSPICIOUS_ACTIVITY,
        "object_refs": [
            "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
            "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
        ],
    }

    # When: Creating a GroupingModel
    grouping = GroupingModel(**data)

    # Then: The model should have the expected values
    assert grouping.name == "Suspicious Activity Group"  # noqa: S101
    assert grouping.description.startswith("A collection of indicators")  # noqa: S101
    assert grouping.context == GroupingContextOV.SUSPICIOUS_ACTIVITY  # noqa: S101
    assert len(grouping.object_refs) == 2  # noqa: S101
