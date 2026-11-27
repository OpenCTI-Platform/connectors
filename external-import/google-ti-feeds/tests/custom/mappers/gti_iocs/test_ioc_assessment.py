"""Tests for the GTI assessment description of IOCs (GTI_EXTENDED_DESCRIPTIONS)."""

import logging
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from connector.src.custom.convert_to_stix.indicator.convert_to_stix_indicator import (
    ConvertToSTIXIndicator,
)
from connector.src.custom.convert_to_stix.report.convert_to_stix_report import (
    ConvertToSTIXReport,
)
from connector.src.custom.mappers.gti_iocs.gti_domain_to_stix_domain import (
    GTIDomainToSTIXDomain,
)
from connector.src.custom.mappers.gti_iocs.ioc_assessment import (
    build_assessment_description,
)
from connector.src.custom.models.gti.gti_assessment_model import (
    ContributingFactors,
    DescriptionCard,
    DescriptionCardLink,
    DescriptionCardTarget,
    GTIAssessment,
    Severity,
    ThreatScore,
    Verdict,
)
from connector.src.custom.models.gti.gti_domain_model import (
    DomainModel,
    GTIDomainData,
)
from connector.src.custom.models.gti.gti_ioc_delta_model import (
    IOCDeltaAttributes,
    IOCDeltaEntry,
)
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

FULL_DESCRIPTION = """Detected by Mandiant analysts.

**Highest impact factor**

- Attributed to Mandiant Threat Actor (high influence). Related: [APT1](https://www.virustotal.com/gui/collection/apt1), Unlinked

**Technical evidence**

- Multi-Engine AV Detections: 24: Engines flagging the file (medium influence)

**GTI assessment**

- Verdict: Malicious
- Severity: High
- Threat score: 92

**Contributing factors**

- Determined malicious by a Mandiant analyst
- Associated with a tracked threat actor
- Mandiant confidence score: 85
- Google Safe Browsing verdict: harmful"""


@pytest.fixture
def assessment() -> GTIAssessment:
    """Return a GTI assessment with every displayed field set."""
    return GTIAssessment(
        verdict=Verdict(value="VERDICT_MALICIOUS"),
        severity=Severity(value="SEVERITY_HIGH"),
        threat_score=ThreatScore(value=92),
        description="Detected by Mandiant analysts.",
        gti_description_cards={
            "HIGHEST_IMPACT_FACTOR": [
                DescriptionCard(
                    influence="high",
                    title="Attributed to Mandiant Threat Actor",
                    sub_title="",
                    collection_type="threat-actor",
                    related_links=[
                        DescriptionCardLink(
                            title="APT1",
                            url=DescriptionCardTarget(
                                object_type="collection", id="apt1"
                            ),
                        ),
                        DescriptionCardLink(
                            title="Unlinked",
                            url=DescriptionCardTarget(object_type="unknown", id="x"),
                        ),
                    ],
                )
            ],
            "TECHNICAL_EVIDENCE": [
                DescriptionCard(
                    influence="medium",
                    title="Multi-Engine AV Detections: 24",
                    sub_title="Engines flagging the file",
                ),
                DescriptionCard(influence="low"),
            ],
            "EMPTY_CATEGORY": [],
        },
        contributing_factors=ContributingFactors(
            mandiant_analyst_malicious=True,
            mandiant_association_actor=True,
            mandiant_osint=False,
            mandiant_confidence_score=85,
            safebrowsing_verdict="harmful",
        ),
    )


def _domain(assessment: GTIAssessment | None) -> GTIDomainData:
    return GTIDomainData(
        id="example.com",
        type="domain",
        attributes=DomainModel(gti_assessment=assessment),
    )


def _domain_mapper(
    assessment: GTIAssessment | None, enabled: bool
) -> GTIDomainToSTIXDomain:
    organization = Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )
    marking = MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )
    return GTIDomainToSTIXDomain(
        _domain(assessment),
        organization,
        marking,
        extended_descriptions=enabled,
    )


def test_build_assessment_description(assessment: GTIAssessment) -> None:
    """GTI summary, cards, verdict, severity, score and true factors are listed."""
    # Given a full GTI assessment
    # When the description is built
    description = build_assessment_description(assessment)
    # Then it lists every available element, skipping false factors
    assert description == FULL_DESCRIPTION  # noqa: S101


def test_build_assessment_description_partial() -> None:
    """Missing elements are left out."""
    # Given an assessment with only a verdict
    assessment = GTIAssessment(verdict=Verdict(value="VERDICT_UNDETECTED"))
    # When the description is built
    description = build_assessment_description(assessment)
    # Then only the verdict is shown
    assert description == "**GTI assessment**\n\n- Verdict: Undetected"  # noqa: S101


@pytest.mark.parametrize(
    "assessment",
    [None, GTIAssessment(), GTIAssessment(contributing_factors=ContributingFactors())],
)
def test_build_assessment_description_empty(
    assessment: GTIAssessment | None,
) -> None:
    """An assessment with nothing to show gives no description."""
    # Given an empty assessment
    # When the description is built
    # Then there is none
    assert build_assessment_description(assessment) is None  # noqa: S101


def test_domain_mapper_describes_observable_and_indicator(
    assessment: GTIAssessment,
) -> None:
    """When enabled, both the observable and the indicator get the description."""
    # Given a domain mapper with the option enabled
    mapper = _domain_mapper(assessment, enabled=True)
    # When the domain is converted
    observable, indicator, _ = mapper.to_stix()
    # Then both carry the assessment description
    assert observable.x_opencti_description == FULL_DESCRIPTION  # noqa: S101
    assert indicator.description == FULL_DESCRIPTION  # noqa: S101


def test_domain_mapper_without_option(assessment: GTIAssessment) -> None:
    """By default, no description is set."""
    # Given a domain mapper with the option disabled
    mapper = _domain_mapper(assessment, enabled=False)
    # When the domain is converted
    observable, indicator, _ = mapper.to_stix()
    # Then neither object has a description
    assert "x_opencti_description" not in observable  # noqa: S101
    assert indicator.description is None  # noqa: S101


def test_report_converter_passes_option_to_ioc_mappers(
    assessment: GTIAssessment,
) -> None:
    """Report sub-entity IOCs follow the configured option."""
    # Given a report converter with the option enabled
    config = MagicMock()
    config.indicator_scoring = "threat_score"
    config.extended_descriptions = True
    converter = ConvertToSTIXReport(
        config=config, logger=logging.getLogger(__name__), tlp_level="white"
    )
    # When the report sub-entities are converted
    stix_objects = converter.convert_subentities_to_stix(
        {"domains": [_domain(assessment)]}, main_entity="report"
    )
    # Then the indicator is described
    indicator = next(obj for obj in stix_objects if obj.type == "indicator")
    assert indicator.description == FULL_DESCRIPTION  # noqa: S101


@pytest.mark.parametrize(
    "enabled, expected",
    [(True, "**GTI assessment**\n\n- Verdict: Malicious"), (False, None)],
)
def test_ioc_delta_converter_description(enabled: bool, expected: str | None) -> None:
    """IOC delta feed indicators follow the configured option."""
    # Given a delta converter
    config = MagicMock()
    config.indicator_scoring = "threat_score"
    config.extended_descriptions = enabled
    config.indicator_subentities = []
    converter = ConvertToSTIXIndicator(
        config=config, logger=logging.getLogger(__name__), tlp_level="white"
    )
    entry = IOCDeltaEntry(
        id="example.com",
        type="domain",
        attributes=IOCDeltaAttributes(
            gti_assessment=GTIAssessment(verdict=Verdict(value="VERDICT_MALICIOUS"))
        ),
    )
    # When the entry is converted
    indicator = converter._convert_domain(entry)
    # Then the description matches the option
    assert indicator is not None  # noqa: S101
    assert indicator.description == expected  # noqa: S101


def test_ioc_delta_description_includes_summary_and_factors() -> None:
    """IOC delta entries carry the GTI summary and contributing factors."""
    # Given a delta entry as documented by GTI
    entry = IOCDeltaEntry.model_validate(
        {
            "id": "147.135.242.186",
            "type": "ip_address",
            "attributes": {
                "gti_assessment": {
                    "verdict": {"value": "VERDICT_SUSPICIOUS"},
                    "contributing_factors": {"gti_confidence_score": 79},
                    "description": "This indicator is suspicious.",
                    "gti_description_cards": {
                        "MITIGATING_FACTORS": [
                            {
                                "influence": "benign",
                                "title": "Seen in legitimate software",
                                "sub_title": "",
                                "collection_type": "",
                                "related_links": [],
                            }
                        ]
                    },
                }
            },
        }
    )
    # When the description is built
    description = build_assessment_description(entry.attributes.gti_assessment)
    # Then every section is present
    assert description == (  # noqa: S101
        "This indicator is suspicious.\n\n"
        "**Mitigating factors**\n\n"
        "- Seen in legitimate software (benign influence)\n\n"
        "**GTI assessment**\n\n- Verdict: Suspicious\n\n"
        "**Contributing factors**\n\n- GTI confidence score: 79"
    )
