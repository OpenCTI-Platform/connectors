"""Tests for the verdict gate of IOC indicators (GTI_INDICATOR_MIN_VERDICT)."""

import logging
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from connector.src.custom.convert_to_stix.indicator.convert_to_stix_indicator import (
    ConvertToSTIXIndicator,
)
from connector.src.custom.mappers.gti_iocs.gti_domain_to_stix_domain import (
    GTIDomainToSTIXDomain,
)
from connector.src.custom.mappers.gti_iocs.ioc_scoring import meets_min_verdict
from connector.src.custom.models.gti.gti_assessment_model import (
    GTIAssessment,
    Verdict,
)
from connector.src.custom.models.gti.gti_domain_model import (
    DomainModel,
    GTIDomainData,
)
from connector.src.custom.models.gti.gti_ioc_delta_model import (
    IOCDeltaAttributes,
    IOCDeltaEntry,
    IOCDeltaRelationships,
)
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


def _assessment(verdict: str | None) -> GTIAssessment | None:
    return GTIAssessment(verdict=Verdict(value=verdict)) if verdict else None


@pytest.mark.parametrize(
    "min_verdict, verdict, expected",
    [
        ("any", None, True),
        ("any", "VERDICT_BENIGN", True),
        ("suspicious", "VERDICT_MALICIOUS", True),
        ("suspicious", "VERDICT_SUSPICIOUS", True),
        ("suspicious", "VERDICT_UNDETECTED", False),
        ("suspicious", None, False),
        ("malicious", "VERDICT_MALICIOUS", True),
        ("malicious", "VERDICT_SUSPICIOUS", False),
        ("malicious", "verdict_malicious", True),
    ],
)
def test_meets_min_verdict(
    min_verdict: str, verdict: str | None, expected: bool
) -> None:
    """Only verdicts at or above the minimum qualify."""
    # Given IOC attributes with a verdict
    attributes = DomainModel(gti_assessment=_assessment(verdict))
    # When the verdict is checked
    # Then it matches the minimum
    assert meets_min_verdict(attributes, min_verdict) is expected  # noqa: S101


@pytest.mark.parametrize(
    "min_verdict, expected_types",
    [
        ("any", ["domain-name", "indicator", "relationship"]),
        ("malicious", ["domain-name"]),
    ],
)
def test_collection_ioc_below_min_verdict_is_observable_only(
    min_verdict: str, expected_types: list[str]
) -> None:
    """A collection IOC below the minimum verdict has no indicator."""
    # Given a suspicious domain
    organization = Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )
    marking = MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )
    domain = GTIDomainData(
        id="example.com",
        type="domain",
        attributes=DomainModel(gti_assessment=_assessment("VERDICT_SUSPICIOUS")),
    )
    mapper = GTIDomainToSTIXDomain(
        domain, organization, marking, indicator_min_verdict=min_verdict
    )
    # When it is converted
    stix_objects = mapper.to_stix()
    # Then the indicator follows the minimum verdict
    assert [obj.type for obj in stix_objects] == expected_types  # noqa: S101


@pytest.mark.parametrize(
    "min_verdict, expected_count", [("suspicious", 1), ("malicious", 0)]
)
def test_delta_entry_below_min_verdict_is_skipped(
    min_verdict: str, expected_count: int
) -> None:
    """An IOC delta entry below the minimum verdict is not imported."""
    # Given a delta converter and a suspicious domain entry
    config = MagicMock(
        indicator_min_score=None,
        indicator_require_malware_family=False,
        indicator_require_threat_actor=False,
        indicator_scoring="threat_score",
        indicator_min_verdict=min_verdict,
        extended_descriptions=False,
        indicator_subentities=[],
    )
    converter = ConvertToSTIXIndicator(
        config=config, logger=logging.getLogger(__name__), tlp_level="white"
    )
    entry = IOCDeltaEntry(
        id="example.com",
        type="domain",
        attributes=IOCDeltaAttributes(gti_assessment=_assessment("VERDICT_SUSPICIOUS")),
        relationships=IOCDeltaRelationships(),
    )
    # When it is converted
    stix_objects = converter.convert(entry.model_dump())
    # Then the indicator follows the minimum verdict
    indicators = [obj for obj in stix_objects if obj.type == "indicator"]
    assert len(indicators) == expected_count  # noqa: S101
