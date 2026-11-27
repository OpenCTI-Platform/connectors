"""Tests for the GTI evidence added to IOC to threat relationship descriptions."""

import logging
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from connector.src.custom.configs.converter_config_common import (
    clear_context,
    related_to_relationship,
    set_context,
)
from connector.src.custom.convert_to_stix.convert_to_stix_base import ioc_data_by_value
from connector.src.custom.convert_to_stix.indicator.convert_to_stix_indicator import (
    ConvertToSTIXIndicator,
)
from connector.src.custom.convert_to_stix.report.convert_to_stix_report import (
    ConvertToSTIXReport,
)
from connector.src.custom.mappers.gti_iocs.gti_domain_to_stix_domain import (
    GTIDomainToSTIXDomain,
)
from connector.src.custom.mappers.gti_iocs.gti_file_to_stix_file import (
    GTIFileToSTIXFile,
)
from connector.src.custom.mappers.relationship_reasons import (
    gti_collection_id,
    ioc_threat_evidence,
    set_relationship_descriptions,
)
from connector.src.custom.models.gti.gti_assessment_model import GTIAssessment
from connector.src.custom.models.gti.gti_domain_model import (
    DomainModel,
    GTIDomainData,
)
from connector.src.custom.models.gti.gti_file_model import FileModel, GTIFileData
from connector.src.stix.octi.models.intrusion_set_model import OctiIntrusionSetModel
from connector.src.stix.octi.models.malware_model import OctiMalwareModel
from connector.src.utils.converters.generic_converter import GenericConverter
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

ACTOR_ID = "threat-actor--5ac9e40f-5f28-5f4f-a1b0-10b1b0c9b42e"
ACTOR_CARD = {
    "influence": "high",
    "title": "Attributed to Mandiant Threat Actor",
    "related_links": [
        {"title": "APT1", "url": {"object_type": "collection", "id": ACTOR_ID}}
    ],
}
MALWARE_CARD = {
    "influence": "medium",
    "title": "Associated with Malware Family",
    "related_links": [
        {"title": "EMOTET", "url": {"object_type": "collection", "id": "other"}}
    ],
}


def _assessment(**factors: bool) -> GTIAssessment:
    return GTIAssessment.model_validate(
        {
            "gti_description_cards": {
                "HIGHEST_IMPACT_FACTOR": [ACTOR_CARD],
                "TECHNICAL_EVIDENCE": [MALWARE_CARD],
            },
            "contributing_factors": factors,
        }
    )


@pytest.fixture(autouse=True)
def enabled_descriptions() -> Iterator[None]:
    """Enable relationship descriptions for each test, then restore the default."""
    set_relationship_descriptions(True)
    yield
    set_relationship_descriptions(False)


@pytest.mark.parametrize(
    "threat_type, name, threat_id, expected",
    [
        (
            "intrusion-set",
            None,
            ACTOR_ID,
            "Evidence: GTI explanation card 'Attributed to Mandiant Threat Actor' "
            "(high influence); contributing factor 'Associated with a tracked threat "
            "actor'.",
        ),
        (
            "malware",
            "emotet",
            None,
            "Evidence: GTI explanation card 'Associated with Malware Family' "
            "(medium influence).",
        ),
        ("malware", "Other", "unknown", None),
    ],
)
def test_ioc_threat_evidence(
    threat_type: str, name: str | None, threat_id: str | None, expected: str | None
) -> None:
    """Cards linking to the threat, by GTI ID or name, and matching factors are quoted."""
    # Given an IOC assessment with cards and an actor association
    assessment = _assessment(mandiant_association_actor=True)
    # When the evidence for a threat is built
    # Then only the cards and factors about that threat are quoted
    assert (  # noqa: S101
        ioc_threat_evidence(assessment, threat_type, name, threat_id) == expected
    )
    assert ioc_threat_evidence(None, threat_type, name, threat_id) is None  # noqa: S101


def test_gti_collection_id() -> None:
    """The GTI collection ID comes from the GTI external reference."""
    # Given intrusion sets with and without a GTI link
    linked = OctiIntrusionSetModel.create(
        name="APT1",
        organization_id=f"identity--{uuid4()}",
        marking_ids=[],
        external_references=[
            {
                "source_name": "Google Threat Intelligence",
                "url": f"https://www.virustotal.com/gui/collection/{ACTOR_ID}",
            }
        ],
    )
    unlinked = OctiIntrusionSetModel.create(
        name="APT1", organization_id=f"identity--{uuid4()}", marking_ids=[]
    )
    # When the GTI ID is read
    # Then it is found only from the GTI link
    assert gti_collection_id(linked) == ACTOR_ID  # noqa: S101
    assert gti_collection_id(unlinked) is None  # noqa: S101


def test_collection_ioc_link_quotes_evidence() -> None:
    """A threat actor IOC link quotes the cards of the IOC pointing to the actor."""
    # Given a domain of a threat actor, with a card attributing it to the actor
    organization = Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )
    marking = MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )
    intrusion_set = OctiIntrusionSetModel.create(
        name="APT1", organization_id=organization.id, marking_ids=[]
    )
    mapper = GTIDomainToSTIXDomain(
        GTIDomainData(
            id="example.com",
            type="domain",
            attributes=DomainModel(gti_assessment=_assessment()),
        ),
        organization,
        marking,
    )
    set_context("intrusion_set", intrusion_set)
    try:
        # When the relationships to the actor are created
        postprocess = related_to_relationship(GTIDomainToSTIXDomain, "intrusion_set")
        relationships = [
            obj
            for obj in postprocess(mapper.to_stix(), mapper=mapper)
            if getattr(obj, "relationship_type", None) in ("indicates", "related-to")
        ]
    finally:
        clear_context("intrusion_set")
    # Then each quotes the card
    assert relationships  # noqa: S101
    for relationship in relationships:
        assert relationship.description.endswith(  # noqa: S101
            "Evidence: GTI explanation card 'Attributed to Mandiant Threat Actor' "
            "(high influence)."
        )


def test_generic_converter_passes_mapper() -> None:
    """Postprocessing functions with a mapper parameter get the mapper."""
    # Given a postprocessing function asking for the mapper
    received: dict[str, Any] = {}

    def postprocess(output: Any, mapper: Any = None) -> Any:
        received["mapper"] = mapper
        return output

    converter = GenericConverter(MagicMock(postprocessing_function=postprocess))
    mapper = object()
    # When the output is postprocessed
    converter._postprocess_output(["output"], mapper)
    # Then the mapper is passed
    assert received["mapper"] is mapper  # noqa: S101


def test_delta_link_quotes_evidence() -> None:
    """An IOC delta malware link quotes the card of the IOC naming the malware."""
    # Given a delta entry linked to EMOTET, with a card naming it
    config = MagicMock(
        relationship_descriptions=True,
        indicator_min_score=None,
        indicator_require_malware_family=False,
        indicator_require_threat_actor=False,
        indicator_min_verdict="any",
        indicator_scoring="threat_score",
        extended_descriptions=False,
        ioc_tags_as_labels=False,
        indicator_subentities=["malware_families"],
        indicator_infrastructure=[],
    )
    converter = ConvertToSTIXIndicator(
        config=config, logger=logging.getLogger(__name__), tlp_level="white"
    )
    entry = {
        "id": "example.com",
        "type": "domain",
        "attributes": {"gti_assessment": _assessment().model_dump()},
        "relationships": {
            "malware_families": {
                "data": [
                    {
                        "type": "collection",
                        "id": "malware--1",
                        "attributes": {"name": "emotet"},
                    }
                ]
            }
        },
    }
    # When it is converted
    relationship = next(
        obj for obj in converter.convert(entry) if obj.type == "relationship"
    )
    # Then the description ends with the evidence
    assert relationship.description.endswith(  # noqa: S101
        "Evidence: GTI explanation card 'Associated with Malware Family' "
        "(medium influence)."
    )


def test_sandbox_evidence_for_malware() -> None:
    """File sandbox verdicts naming the malware family are quoted, others ignored."""
    # Given sandbox verdicts of a file, one naming EMOTET
    verdicts = FileModel(
        sandbox_verdicts={
            "Zenbox": {
                "category": "malicious",
                "confidence": 80,
                "malware_names": ["Emotet"],
                "sandbox_name": "Zenbox",
            },
            "Other": {"category": "malicious", "malware_names": ["TrickBot"]},
        }
    ).sandbox_verdicts
    # When the evidence for the malware is built
    # Then the matching sandbox is quoted
    assert ioc_threat_evidence(
        None, "malware", "EMOTET", None, verdicts
    ) == (  # noqa: S101
        "Evidence: sandbox 'Zenbox' detects Emotet (malicious, confidence 80)."
    )
    # And sandboxes are not evidence for other threat types
    assert (  # noqa: S101
        ioc_threat_evidence(None, "intrusion-set", "EMOTET", None, verdicts) is None
    )


def test_collection_file_link_quotes_sandbox() -> None:
    """A malware family file link quotes the sandbox verdicts naming the family."""
    # Given a file of a malware family, detected by a sandbox
    organization = Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )
    marking = MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )
    sha256 = "a" * 64
    mapper = GTIFileToSTIXFile(
        GTIFileData(
            id=sha256,
            type="file",
            attributes=FileModel(
                sha256=sha256,
                sandbox_verdicts={
                    "Zenbox": {"category": "malicious", "malware_names": ["emotet"]}
                },
            ),
        ),
        organization,
        marking,
    )
    malware = OctiMalwareModel.create(
        name="EMOTET",
        is_family=True,
        malware_types=[],
        organization_id=organization.id,
        marking_ids=[],
    )
    # When the evidence for the malware is read
    # Then the sandbox is quoted
    assert mapper.relationship_evidence(malware) == (  # noqa: S101
        "Evidence: sandbox 'Zenbox' detects emotet (malicious)."
    )


def test_ioc_data_by_value() -> None:
    """IOCs are indexed by GTI ID, URLs by URL."""
    # Given report IOCs
    domain = GTIDomainData(id="example.com", type="domain", attributes=DomainModel())
    url = MagicMock(id="url-id", attributes=MagicMock(url="http://example.com/a"))
    # When they are indexed
    index = ioc_data_by_value({"domains": [domain], "urls": [url], "reports": [1]})
    # Then each is found by the value naming its STIX objects
    assert index == {"example.com": domain, "http://example.com/a": url}  # noqa: S101


def test_co_occurrence_link_quotes_ioc_evidence() -> None:
    """A report IOC linked to an actor of the report quotes the card naming the actor."""
    # Given a report domain with a card attributing it to APT1, and APT1
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
        attributes=DomainModel(gti_assessment=_assessment()),
    )
    _, indicator, _ = GTIDomainToSTIXDomain(domain, organization, marking).to_stix()
    intrusion_set = OctiIntrusionSetModel.create(
        name="APT1", organization_id=organization.id, marking_ids=[]
    )
    converter = ConvertToSTIXReport(
        config=MagicMock(relationship_descriptions=True),
        logger=logging.getLogger(__name__),
        tlp_level="white",
    )
    # When they are linked as co-occurring in the report
    (relationship,) = converter.create_co_occurrence_relationships(
        [indicator, intrusion_set],
        {("indicator", "intrusion-set"): "indicates"},
        ioc_data=ioc_data_by_value({"domains": [domain]}),
    )
    # Then the inferred link also quotes the GTI evidence
    assert relationship.description.startswith(  # noqa: S101
        "Inferred by the connector, not stated by GTI:"
    )
    assert relationship.description.endswith(  # noqa: S101
        "Evidence: GTI explanation card 'Attributed to Mandiant Threat Actor' "
        "(high influence)."
    )
