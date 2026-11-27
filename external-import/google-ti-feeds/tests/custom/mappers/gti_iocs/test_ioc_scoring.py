"""Tests for the configurable IOC scoring strategies."""

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
from connector.src.custom.mappers.gti_iocs.ioc_scoring import (
    compute_ioc_score,
    score_from_detection_stats,
    score_from_gti_verdict,
)
from connector.src.custom.models.gti.gti_assessment_model import (
    ContributingFactors,
    GTIAssessment,
    LastAnalysisStats,
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


def _domain_attributes(
    threat_score: int | None = None,
    gti_confidence_score: int | None = None,
    mandiant_confidence_score: int | None = None,
    verdict: str | None = None,
    severity: str | None = None,
    stats: LastAnalysisStats | None = None,
) -> DomainModel:
    return DomainModel(
        gti_assessment=GTIAssessment(
            threat_score=ThreatScore(value=threat_score),
            verdict=Verdict(value=verdict),
            severity=Severity(value=severity),
            contributing_factors=ContributingFactors(
                gti_confidence_score=gti_confidence_score,
                mandiant_confidence_score=mandiant_confidence_score,
            ),
        ),
        last_analysis_stats=stats,
    )


# Scenario: threat_score strategy falls back to the confidence scores
@pytest.mark.parametrize(
    "threat_score, gti_confidence_score, mandiant_confidence_score, expected",
    [
        (70, 80, 90, 70),
        (None, 80, 90, 80),
        (None, None, 90, 90),
        (None, None, None, None),
    ],
)
def test_threat_score_strategy(
    threat_score: int | None,
    gti_confidence_score: int | None,
    mandiant_confidence_score: int | None,
    expected: int | None,
) -> None:
    """Threat score, then GTI confidence score, then Mandiant confidence score."""
    # Given IOC attributes with the given scores
    attributes = _domain_attributes(
        threat_score=threat_score,
        gti_confidence_score=gti_confidence_score,
        mandiant_confidence_score=mandiant_confidence_score,
    )
    # When the score is computed
    score = compute_ioc_score(attributes, "threat_score")
    # Then the expected source is used
    assert score == expected  # noqa: S101


# Scenario: gti_derived strategy maps verdict and severity
@pytest.mark.parametrize(
    "verdict, severity, expected",
    [
        ("VERDICT_MALICIOUS", "SEVERITY_HIGH", 90),
        ("VERDICT_MALICIOUS", "SEVERITY_MEDIUM", 85),
        ("VERDICT_MALICIOUS", "SEVERITY_LOW", 80),
        ("VERDICT_MALICIOUS", None, 80),
        ("VERDICT_SUSPICIOUS", "SEVERITY_HIGH", 70),
        ("VERDICT_UNDETECTED", None, 20),
        ("VERDICT_BENIGN", "SEVERITY_NONE", 0),
        ("VERDICT_UNKNOWN", "SEVERITY_HIGH", None),
        (None, "SEVERITY_HIGH", None),
    ],
)
def test_score_from_gti_verdict(
    verdict: str | None, severity: str | None, expected: int | None
) -> None:
    """Verdict sets the base score, severity adds a bonus."""
    # Given a GTI assessment with a verdict and a severity
    attributes = _domain_attributes(verdict=verdict, severity=severity)
    # When the GTI derived score is computed
    score = score_from_gti_verdict(attributes.gti_assessment)
    # Then it matches the mapping
    assert score == expected  # noqa: S101


# Scenario: average_detection strategy uses the share of flagging engines
@pytest.mark.parametrize(
    "stats, expected",
    [
        (LastAnalysisStats(malicious=50, suspicious=0, harmless=25, undetected=25), 50),
        (LastAnalysisStats(malicious=10, suspicious=20, harmless=0, undetected=70), 20),
        (LastAnalysisStats(malicious=0, suspicious=0, harmless=60, undetected=40), 0),
        (LastAnalysisStats(malicious=0, suspicious=0, harmless=0, undetected=0), None),
        (LastAnalysisStats(timeout=5), None),
        (None, None),
    ],
)
def test_score_from_detection_stats(
    stats: LastAnalysisStats | None, expected: int | None
) -> None:
    """Malicious counts fully, suspicious counts half."""
    # Given analysis stats
    # When the average detection score is computed
    score = score_from_detection_stats(stats)
    # Then it matches the weighted ratio
    assert score == expected  # noqa: S101


# Scenario: a strategy without data falls back to threat_score
@pytest.mark.parametrize("strategy", ["gti_derived", "average_detection"])
def test_strategy_without_data_falls_back_to_threat_score(strategy: str) -> None:
    """Missing verdict or stats does not leave the IOC without a score."""
    # Given IOC attributes with only a threat score
    attributes = _domain_attributes(threat_score=42)
    # When the score is computed with a strategy lacking data
    score = compute_ioc_score(attributes, strategy)
    # Then the threat score is used
    assert score == 42  # noqa: S101


def test_compute_ioc_score_without_attributes() -> None:
    """IOCs without attributes have no score."""
    # Given no attributes
    # When the score is computed
    # Then there is no score
    assert compute_ioc_score(None, "gti_derived") is None  # noqa: S101


def test_domain_mapper_uses_configured_strategy() -> None:
    """The observable and the indicator get the score of the configured strategy."""
    # Given a domain with a threat score and detection stats
    domain = GTIDomainData(
        id="example.com",
        type="domain",
        attributes=_domain_attributes(
            threat_score=10,
            stats=LastAnalysisStats(
                malicious=3, suspicious=0, harmless=1, undetected=0
            ),
        ),
    )
    organization = Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )
    marking = MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )
    mapper = GTIDomainToSTIXDomain(
        domain, organization, marking, indicator_scoring="average_detection"
    )
    # When the domain is converted
    observable, indicator, _ = mapper.to_stix()
    # Then both objects carry the average detection score
    assert observable.x_opencti_score == 75  # noqa: S101
    assert indicator.custom_properties["x_opencti_score"] == 75  # noqa: S101


def test_ioc_delta_converter_uses_configured_strategy() -> None:
    """The IOC delta feed indicators get the score of the configured strategy."""
    # Given a delta converter configured with gti_derived
    config = MagicMock()
    config.indicator_scoring = "gti_derived"
    config.indicator_subentities = []
    converter = ConvertToSTIXIndicator(
        config=config, logger=logging.getLogger(__name__), tlp_level="white"
    )
    entry = IOCDeltaEntry(
        id="example.com",
        type="domain",
        attributes=IOCDeltaAttributes(
            gti_assessment=GTIAssessment(
                verdict=Verdict(value="VERDICT_SUSPICIOUS"),
                severity=Severity(value="SEVERITY_MEDIUM"),
                threat_score=ThreatScore(value=10),
            )
        ),
    )
    # When the entry is converted
    indicator = converter._convert_domain(entry)
    # Then the score comes from the verdict and severity
    assert indicator is not None  # noqa: S101
    assert indicator.score == 65  # noqa: S101


def test_report_converter_passes_strategy_to_ioc_mappers() -> None:
    """Report sub-entity IOCs are scored with the configured strategy."""
    # Given a report converter configured with gti_derived
    config = MagicMock()
    config.indicator_scoring = "gti_derived"
    converter = ConvertToSTIXReport(
        config=config, logger=logging.getLogger(__name__), tlp_level="white"
    )
    domain = GTIDomainData(
        id="example.com",
        type="domain",
        attributes=_domain_attributes(
            threat_score=10, verdict="VERDICT_MALICIOUS", severity="SEVERITY_HIGH"
        ),
    )
    # When the report sub-entities are converted
    stix_objects = converter.convert_subentities_to_stix(
        {"domains": [domain]}, main_entity="report"
    )
    # Then the observable carries the GTI derived score
    observable = next(obj for obj in stix_objects if obj.type == "domain-name")
    assert observable.x_opencti_score == 90  # noqa: S101


def test_ioc_delta_entry_uses_gti_confidence_score() -> None:
    """IOC delta entries parse contributing factors for the fallback."""
    # Given a delta entry with only a GTI confidence score
    entry = IOCDeltaEntry.model_validate(
        {
            "id": "147.135.242.186",
            "type": "ip_address",
            "attributes": {
                "gti_assessment": {"contributing_factors": {"gti_confidence_score": 79}}
            },
        }
    )
    # When the score is computed
    score = compute_ioc_score(entry.attributes, "threat_score")
    # Then the GTI confidence score is used
    assert score == 79  # noqa: S101
