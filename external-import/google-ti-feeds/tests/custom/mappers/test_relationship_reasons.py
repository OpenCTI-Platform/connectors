"""Tests for the relationship descriptions stating why a relationship exists."""

import logging
from collections.abc import Iterator
from datetime import datetime, timezone
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from connector.src.custom.configs.converter_config_common import (
    clear_context,
    set_context,
    uses_relationship,
)
from connector.src.custom.convert_to_stix.indicator.convert_to_stix_indicator import (
    ConvertToSTIXIndicator,
)
from connector.src.custom.convert_to_stix.report.convert_to_stix_report import (
    ConvertToSTIXReport,
)
from connector.src.custom.mappers.gti_malwares.gti_malware_family_to_stix_malware import (
    GTIMalwareFamilyToSTIXMalware,
)
from connector.src.custom.mappers.relationship_reasons import (
    display_name,
    ip_autonomous_system_reason,
    ip_country_reason,
    optional_reason,
    set_relationship_descriptions,
    with_description,
)
from connector.src.custom.models.gti.gti_ioc_delta_model import (
    IOCDeltaAttributes,
    IOCDeltaEntry,
)
from connector.src.stix.octi.models.intrusion_set_model import OctiIntrusionSetModel
from connector.src.stix.octi.models.malware_model import OctiMalwareModel
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from stix2.v21 import (  # type: ignore
    AutonomousSystem,
    File,
    Identity,
    IPv4Address,
    MarkingDefinition,
)


@pytest.fixture(autouse=True)
def enabled_descriptions() -> Iterator[None]:
    """Enable relationship descriptions for each test, then restore the default."""
    set_relationship_descriptions(True)
    yield
    set_relationship_descriptions(False)


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


@pytest.fixture
def intrusion_set_context(organization: Identity) -> Iterator[object]:
    """Set an intrusion set as the converter context, then clear it."""
    intrusion_set = OctiIntrusionSetModel.create(
        name="APT Example",
        organization_id=organization.id,
        marking_ids=[],
    )
    set_context("intrusion_set", intrusion_set)
    yield intrusion_set
    clear_context("intrusion_set")


def _malware(organization: Identity, name: str = "EMOTET") -> object:
    return OctiMalwareModel.create(
        name=name,
        is_family=True,
        malware_types=[],
        organization_id=organization.id,
        marking_ids=[],
    )


@pytest.mark.parametrize(
    "obj, expected",
    [
        (IPv4Address(value="203.0.113.7"), "203.0.113.7"),
        (File(hashes={"SHA-256": "a" * 64}), "a" * 64),
        (AutonomousSystem(number=16276), "AS16276"),
    ],
)
def test_display_name(obj: object, expected: str) -> None:
    """Objects without a name are shown by value, hash or AS number."""
    # Given a STIX object
    # When its name is resolved
    # Then the most readable identifier is used
    assert display_name(obj) == expected  # noqa: S101


def test_with_description_keeps_existing_description(organization: Identity) -> None:
    """A description set by the mapper is not replaced."""
    # Given a relationship with a description
    relationship = OctiRelationshipModel.create(
        relationship_type="uses",
        source_ref=f"intrusion-set--{uuid4()}",
        target_ref=f"malware--{uuid4()}",
        organization_id=organization.id,
        marking_ids=[],
        created=datetime.now(tz=timezone.utc),
        modified=datetime.now(tz=timezone.utc),
        description="Set by the mapper.",
    )
    # When a reason is added
    # Then the mapper description is kept
    assert (  # noqa: S101
        with_description(relationship, "Reason.").description == "Set by the mapper."
    )
    assert with_description("not a model", "Reason.") == "not a model"  # noqa: S101


def test_gti_association_reason(
    organization: Identity, intrusion_set_context: object
) -> None:
    """Links to entities a GTI collection lists are described as stated by GTI."""
    # Given a malware family listed by the intrusion set context
    postprocess = uses_relationship(GTIMalwareFamilyToSTIXMalware, "intrusion_set")
    # When the relationship is created
    relationship = postprocess([_malware(organization)])[-1]
    # Then its description states the GTI association
    assert relationship.description == (  # noqa: S101
        "Stated by GTI: Google Threat Intelligence lists the malware 'EMOTET' "
        "among the related objects of the intrusion set 'APT Example'."
    )


def test_co_occurrence_reason(organization: Identity) -> None:
    """Co-occurrence links are described as inferred, naming the container."""
    # Given an intrusion set and a malware of the same report
    converter = ConvertToSTIXReport(
        config=MagicMock(relationship_descriptions=True),
        logger=logging.getLogger(__name__),
        tlp_level="white",
    )
    intrusion_set = OctiIntrusionSetModel.create(
        name="APT Example", organization_id=organization.id, marking_ids=[]
    )
    report = MagicMock(type="report")
    report.name = "Operation Example"
    # When they are linked
    (relationship,) = converter.create_co_occurrence_relationships(
        [intrusion_set, _malware(organization)],
        {("intrusion-set", "malware"): "uses"},
        container=report,
    )
    # Then the description says the link is inferred, and from where
    assert relationship.description == (  # noqa: S101
        "Inferred by the connector, not stated by GTI: the intrusion set "
        "'APT Example' and the malware 'EMOTET' are both referenced by the "
        "report 'Operation Example'."
    )


def test_ioc_delta_association_reason() -> None:
    """IOC delta threat links are described as stated by the deltas feed."""
    # Given a delta converter linking malware families
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
    )
    converter = ConvertToSTIXIndicator(
        config=config, logger=logging.getLogger(__name__), tlp_level="white"
    )
    entry = IOCDeltaEntry.model_validate(
        {
            "id": "example.com",
            "type": "domain",
            "attributes": IOCDeltaAttributes().model_dump(),
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
    )
    # When the entry is converted
    relationship = next(
        obj
        for obj in converter.convert(entry.model_dump())
        if obj.type == "relationship"
    )
    # Then the description states where the link comes from
    assert relationship.description == (  # noqa: S101
        "Stated by GTI: the IOC deltas feed lists the malware 'EMOTET' among the "
        "relationships of this IOC."
    )


def test_ip_link_reasons() -> None:
    """IP autonomous system and country links quote the GTI values."""
    # Given the GTI network values of an IP
    # When the reasons are built
    # Then they quote the GTI values
    assert ip_autonomous_system_reason(16276, "OVH SAS") == (  # noqa: S101
        "Stated by GTI: GTI lists AS16276 (OVH SAS) as the autonomous system of "
        "this IP."
    )
    assert ip_autonomous_system_reason(16276, None) == (  # noqa: S101
        "Stated by GTI: GTI lists AS16276 as the autonomous system of this IP."
    )
    assert ip_country_reason("France", "FR") == (  # noqa: S101
        "Stated by GTI: GTI geolocates this IP in France (country code FR)."
    )


def test_descriptions_disabled_by_default(organization: Identity) -> None:
    """Without the option, no relationship description is written (#5775)."""
    # Given a converter without GTI_RELATIONSHIP_DESCRIPTIONS
    ConvertToSTIXReport(
        config=MagicMock(), logger=logging.getLogger(__name__), tlp_level="white"
    )
    relationship = OctiRelationshipModel.create(
        relationship_type="uses",
        source_ref=f"intrusion-set--{uuid4()}",
        target_ref=f"malware--{uuid4()}",
        organization_id=organization.id,
        marking_ids=[],
        created=datetime.now(tz=timezone.utc),
        modified=datetime.now(tz=timezone.utc),
    )
    # When reasons are requested
    # Then none is written
    assert optional_reason("Reason.") is None  # noqa: S101
    assert with_description(relationship, "Reason.").description is None  # noqa: S101
