"""Tests for the intrusion set co-occurrence relationships of reports and campaigns."""

import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from connector.src.custom.convert_to_stix.report.convert_to_stix_report import (
    ConvertToSTIXReport,
)
from connector.src.custom.models.gti.gti_attack_technique_id_model import (
    GTIAttackTechniqueIDData,
)
from connector.src.custom.orchestrators.campaign.orchestrator_campaign import (
    OrchestratorCampaign,
)
from connector.src.custom.orchestrators.report.orchestrator_report import (
    OrchestratorReport,
)

INTRUSION_SET_ID = "intrusion-set--00000000-0000-4000-8000-000000000001"
MALWARE_ID = "malware--00000000-0000-4000-8000-000000000002"
TOOL_ID = "tool--00000000-0000-4000-8000-000000000003"
ATTACK_PATTERN_ID = "attack-pattern--00000000-0000-4000-8000-000000000004"
VULNERABILITY_ID = "vulnerability--00000000-0000-4000-8000-000000000005"
INDICATOR_ID = "indicator--00000000-0000-4000-8000-000000000006"

EXPECTED_LINKS = {
    (INTRUSION_SET_ID, "uses", MALWARE_ID),
    (INTRUSION_SET_ID, "uses", TOOL_ID),
    (INTRUSION_SET_ID, "uses", ATTACK_PATTERN_ID),
    (INTRUSION_SET_ID, "targets", VULNERABILITY_ID),
}


def _obj(stix_type: str, stix_id: str) -> Any:
    return SimpleNamespace(type=stix_type, id=stix_id)


@pytest.fixture
def subentities() -> list[Any]:
    """Return converted sub-entities of a report or campaign."""
    return [
        _obj("intrusion-set", INTRUSION_SET_ID),
        _obj("malware", MALWARE_ID),
        _obj("tool", TOOL_ID),
        _obj("attack-pattern", ATTACK_PATTERN_ID),
        _obj("vulnerability", VULNERABILITY_ID),
        _obj("indicator", INDICATOR_ID),
    ]


def _config(**options: bool) -> MagicMock:
    return MagicMock(
        **{
            "ioc_link_to_threats": False,
            "intrusion_set_link_to_capabilities": False,
            **options,
        }
    )


def _links(relationships: list[Any]) -> set[tuple[str, str, str]]:
    return {(r.source_ref, r.relationship_type, r.target_ref) for r in relationships}


def test_report_links_intrusion_sets_to_capabilities(subentities: list[Any]) -> None:
    """Intrusion sets use the malware, tools and techniques and target the CVEs."""
    # Given a report orchestrator with the option enabled
    orchestrator = OrchestratorReport(
        work_manager=MagicMock(),
        logger=logging.getLogger(__name__),
        config=_config(intrusion_set_link_to_capabilities=True),
        tlp_level="white",
    )
    report = SimpleNamespace(type="report", id="report--1", object_refs=[])
    # When co-occurring entities are linked
    relationships = orchestrator._link_co_occurring_entities([report], subentities)
    # Then only the intrusion set relationships are created and added to the report
    assert _links(relationships) == EXPECTED_LINKS  # noqa: S101
    assert report.object_refs == [r.id for r in relationships]  # noqa: S101


def test_both_link_options_combine(subentities: list[Any]) -> None:
    """IOC and intrusion set links are created together when both are enabled."""
    # Given a report orchestrator with both options enabled
    orchestrator = OrchestratorReport(
        work_manager=MagicMock(),
        logger=logging.getLogger(__name__),
        config=_config(
            ioc_link_to_threats=True, intrusion_set_link_to_capabilities=True
        ),
        tlp_level="white",
    )
    report = SimpleNamespace(type="report", id="report--1", object_refs=[])
    # When co-occurring entities are linked
    relationships = orchestrator._link_co_occurring_entities([report], subentities)
    # Then the indicator is also linked to the intrusion set and the malware
    assert _links(relationships) == EXPECTED_LINKS | {  # noqa: S101
        (INDICATOR_ID, "indicates", INTRUSION_SET_ID),
        (INDICATOR_ID, "indicates", MALWARE_ID),
    }


def test_campaign_rules_include_intrusion_set_capabilities() -> None:
    """Campaigns get the intrusion set rules when the option is enabled."""
    # Given a campaign orchestrator with the option enabled
    orchestrator = OrchestratorCampaign(
        work_manager=MagicMock(),
        logger=logging.getLogger(__name__),
        config=_config(intrusion_set_link_to_capabilities=True),
        tlp_level="white",
    )
    # When the co-occurrence rules are resolved
    rules = orchestrator._co_occurrence_relationship_types(("intrusion-set", "malware"))
    # Then they are the intrusion set rules
    assert rules == {  # noqa: S101
        ("intrusion-set", "malware"): "uses",
        ("intrusion-set", "tool"): "uses",
        ("intrusion-set", "attack-pattern"): "uses",
        ("intrusion-set", "vulnerability"): "targets",
    }


def test_report_attack_patterns_match_rule_type() -> None:
    """Attack patterns converted for reports have the type the rules target."""
    # Given the ID-only attack techniques of a report
    converter = ConvertToSTIXReport(
        config=MagicMock(), logger=logging.getLogger(__name__), tlp_level="white"
    )
    # (a technique without a name is skipped, see #8012)
    techniques = GTIAttackTechniqueIDData.from_id_list(
        ["T1059"], names={"T1059": "Command and Scripting Interpreter"}
    )
    # When they are converted
    stix_objects = converter.convert_subentities_to_stix(
        {"attack_techniques": [techniques]}, main_entity="report"
    )
    # Then they are attack-pattern objects
    assert stix_objects  # noqa: S101
    assert {obj.type for obj in stix_objects} == {"attack-pattern"}  # noqa: S101
