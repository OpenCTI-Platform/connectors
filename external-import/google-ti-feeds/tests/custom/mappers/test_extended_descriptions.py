"""Tests for the GTI details appended to descriptions by GTI_EXTENDED_DESCRIPTIONS."""

import json
import logging
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from connector.src.custom.convert_to_stix.report.convert_to_stix_report import (
    ConvertToSTIXReport,
)
from connector.src.custom.mappers.description_details import (
    bullet_section,
    details_section,
    format_date,
    join_sections,
)
from connector.src.custom.mappers.gti_malwares.gti_malware_family_to_stix_malware import (
    GTIMalwareFamilyToSTIXMalware,
)
from connector.src.custom.mappers.gti_vulnerabilities.gti_vulnerability_to_stix_vulnerability import (
    GTIVulnerabilityToSTIXVulnerability,
)
from connector.src.custom.models.gti.gti_malware_family_model import (
    GTIMalwareFamilyData,
)
from connector.src.custom.models.gti.gti_vulnerability_model import (
    GTIVulnerabilityData,
)
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

DEBUG_RESPONSES = Path(__file__).parents[1] / "debug_responses"

# 2024-01-15 and 2024-02-05 UTC
ADDED_DATE = 1705276800
DUE_DATE = 1707091200


def _first_entity(file_name: str) -> dict[str, Any]:
    with open(DEBUG_RESPONSES / file_name, encoding="utf-8") as file:
        return json.load(file)["response"]["data"][0]


def _vulnerability(**attributes: Any) -> GTIVulnerabilityData:
    data = _first_entity("main_vulnerabilities_1a6f110bd333906d.json")
    data["attributes"].update(attributes)
    return GTIVulnerabilityData.model_validate(data)


def _malware_family(**attributes: Any) -> GTIMalwareFamilyData:
    data = _first_entity("main_malware_families_39b26d46dfe989dc.json")
    data["attributes"].update(attributes)
    return GTIMalwareFamilyData.model_validate(data)


@pytest.fixture
def organization() -> Identity:
    """Return the author identity."""
    return Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )


@pytest.fixture
def marking() -> MarkingDefinition:
    """Return a marking definition."""
    return MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )


# Scenario: shared Markdown helpers
def test_details_section_skips_empty_values() -> None:
    """Empty values are left out and lists are comma-joined."""
    # Given details with empty and list values
    details = {"A": "x", "B": None, "C": "", "D": [], "E": ["y", "z"], "F": 0}
    # When the section is built
    section = details_section("Title", details)
    # Then only the non-empty values are listed
    assert section == "**Title**\n\n- A: x\n- E: y, z\n- F: 0"  # noqa: S101


def test_empty_sections() -> None:
    """Sections without content are None and skipped when joined."""
    # Given empty inputs
    # When sections are built and joined
    # Then nothing is produced
    assert details_section("Title", {"A": None}) is None  # noqa: S101
    assert bullet_section("Title", []) is None  # noqa: S101
    assert join_sections(None, " ", "text") == "text"  # noqa: S101
    assert join_sections(None, "") is None  # noqa: S101
    assert format_date(None) is None  # noqa: S101
    assert format_date(ADDED_DATE) == "2024-01-15"  # noqa: S101


# Scenario: vulnerability details
def test_vulnerability_description_appends_details(
    organization: Identity, marking: MarkingDefinition
) -> None:
    """The GTI description is kept and followed by the vulnerability details."""
    # Given a vulnerability with exploitation and CISA KEV data
    vulnerability = _vulnerability(
        description="Remote code execution.",
        risk_rating="CRITICAL",
        exploitation_state="Wide",
        exploit_availability="Publicly Available",
        exploitation_consequence="Code Execution",
        exploitation_vectors=["General Network Connectivity"],
        priority="P0",
        date_of_disclosure=None,
        exploitation=None,
        cisa_known_exploited={
            "added_date": ADDED_DATE,
            "due_date": DUE_DATE,
            "ransomware_use": "Known",
        },
        mve_id=None,
        cpes=None,
        available_mitigation=["Patch"],
    )
    mapper = GTIVulnerabilityToSTIXVulnerability(
        vulnerability, organization, marking, extended_descriptions=True
    )
    # When it is converted
    stix_vulnerability = mapper.to_stix()
    # Then the details follow the GTI description
    assert stix_vulnerability.description == (  # noqa: S101
        "Remote code execution.\n\n"
        "**GTI vulnerability details**\n\n"
        "- Risk rating: CRITICAL\n"
        "- Exploitation state: Wide\n"
        "- Exploit availability: Publicly Available\n"
        "- Exploitation consequence: Code Execution\n"
        "- Exploitation vectors: General Network Connectivity\n"
        "- Remediation priority: P0\n"
        "- Added to CISA KEV: 2024-01-15\n"
        "- CISA KEV remediation due: 2024-02-05\n"
        "- Ransomware use: Known\n\n"
        "**Available mitigations**\n\n"
        "- Patch"
    )


def test_vulnerability_uses_predicted_risk_rating(
    organization: Identity, marking: MarkingDefinition
) -> None:
    """The predicted risk rating is used, flagged, when GTI has no analyst rating."""
    # Given a vulnerability with only a predicted risk rating
    vulnerability = _vulnerability(
        description=None, risk_rating="", predicted_risk_rating="High"
    )
    mapper = GTIVulnerabilityToSTIXVulnerability(
        vulnerability, organization, marking, extended_descriptions=True
    )
    # When it is converted
    stix_vulnerability = mapper.to_stix()
    # Then the predicted rating is shown
    assert (
        "- Risk rating: High (predicted)" in stix_vulnerability.description
    )  # noqa: S101


def test_vulnerability_description_unchanged_by_default(
    organization: Identity, marking: MarkingDefinition
) -> None:
    """By default, the GTI description is used as is."""
    # Given a vulnerability with details
    vulnerability = _vulnerability(description="Original.", risk_rating="CRITICAL")
    mapper = GTIVulnerabilityToSTIXVulnerability(vulnerability, organization, marking)
    # When it is converted
    stix_vulnerability = mapper.to_stix()
    # Then the description is untouched
    assert stix_vulnerability.description == "Original."  # noqa: S101


# Scenario: malware family details
def test_malware_description_appends_details(
    organization: Identity, marking: MarkingDefinition
) -> None:
    """Operating systems and detection names follow the GTI description."""
    # Given a malware family with operating systems and repeated detection names
    detection = {"confidence": "confirmed"}
    malware_family = _malware_family(
        description="Backdoor.",
        operating_systems=[
            {"confidence": "confirmed", "value": "Windows"},
            {"confidence": "confirmed", "value": "Linux"},
        ],
        detection_names=[{**detection, "value": f"Name{i % 12}"} for i in range(20)],
    )
    mapper = GTIMalwareFamilyToSTIXMalware(
        malware_family, organization, marking, extended_descriptions=True
    )
    # When it is converted
    malware = mapper.to_stix()
    # Then the distinct values are listed, detection names capped at ten
    names = ", ".join(f"Name{i}" for i in range(10))
    assert malware.description == (  # noqa: S101
        "Backdoor.\n\n"
        "**GTI malware details**\n\n"
        "- Operating systems: Windows, Linux\n"
        f"- Detection names: {names}"
    )


def test_malware_description_unchanged_by_default(
    organization: Identity, marking: MarkingDefinition
) -> None:
    """By default, the GTI description is used as is."""
    # Given a malware family with operating systems
    malware_family = _malware_family(
        description="Backdoor.",
        operating_systems=[{"confidence": "confirmed", "value": "Windows"}],
    )
    mapper = GTIMalwareFamilyToSTIXMalware(malware_family, organization, marking)
    # When it is converted
    malware = mapper.to_stix()
    # Then the description is untouched
    assert malware.description == "Backdoor."  # noqa: S101


# Scenario: the option reaches the sub-entity mappers
@pytest.mark.parametrize(
    "entity_type, expected",
    [
        (
            "malware_families",
            {"enable_malware_aliases": False, "extended_descriptions": True},
        ),
        ("vulnerabilities", {"extended_descriptions": True}),
        ("threat_actors", {"enable_threat_actor_aliases": False}),
        (
            "domains",
            {
                "indicator_scoring": "gti_derived",
                "indicator_min_verdict": "malicious",
                "extended_descriptions": True,
                "ioc_tags_as_labels": True,
            },
        ),
        ("attack_techniques", {}),
    ],
)
def test_mapper_options(entity_type: str, expected: dict[str, Any]) -> None:
    """Each entity type gets only the options its mapper accepts."""
    # Given a converter configuration
    config = MagicMock(
        enable_malware_aliases=False,
        enable_threat_actor_aliases=False,
        indicator_scoring="gti_derived",
        indicator_min_verdict="malicious",
        extended_descriptions=True,
        ioc_tags_as_labels=True,
    )
    logger = logging.getLogger(__name__)
    converter = ConvertToSTIXReport(config=config, logger=logger, tlp_level="white")
    # When the mapper options are resolved
    # Then they match the entity type, and threat actor mappers get the logger
    if entity_type == "threat_actors":
        expected = {**expected, "logger": logger}
    assert converter.mapper_options(entity_type) == expected  # noqa: S101
