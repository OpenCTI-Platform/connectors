"""Tests for the autonomous system of IP IOCs (GTI_IP_LINK_TO_ASN)."""

import logging
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from connector.src.custom.convert_to_stix.report.convert_to_stix_report import (
    ConvertToSTIXReport,
)
from connector.src.custom.mappers.gti_iocs.gti_ip_to_stix_ip import GTIIPToSTIXIP
from connector.src.custom.models.gti.gti_ip_addresses_model import GTIIPData
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

IP = "147.135.242.186"
AS_ATTRIBUTES = {
    "asn": 16276,
    "as_owner": "OVH SAS",
    "regional_internet_registry": "RIPE NCC",
}


def _mapper(enabled: bool, **attributes: Any) -> GTIIPToSTIXIP:
    organization = Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )
    marking = MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )
    ip = GTIIPData(id=IP, type="ip_address", attributes=attributes)
    return GTIIPToSTIXIP(ip, organization, marking, ip_link_to_asn=enabled)


def test_ip_belongs_to_its_autonomous_system() -> None:
    """When enabled, the IP is linked to its autonomous system."""
    # Given an IP with its autonomous system
    mapper = _mapper(True, **AS_ATTRIBUTES)
    # When it is converted
    observable, _, _, autonomous_system, belongs_to = mapper.to_stix()
    # Then the autonomous system carries the GTI details and the IP belongs to it
    assert autonomous_system.number == 16276  # noqa: S101
    assert autonomous_system.name == "OVH SAS"  # noqa: S101
    assert autonomous_system.rir == "RIPE NCC"  # noqa: S101
    assert belongs_to.relationship_type == "belongs-to"  # noqa: S101
    assert belongs_to.source_ref == observable.id  # noqa: S101
    assert belongs_to.target_ref == autonomous_system.id  # noqa: S101


def test_autonomous_system_id_is_deterministic() -> None:
    """The same autonomous system gets the same ID on every run."""
    # Given two conversions of the same IP
    # When they are converted
    first = _mapper(True, **AS_ATTRIBUTES).to_stix()[3]
    second = _mapper(True, **AS_ATTRIBUTES).to_stix()[3]
    # Then the IDs match
    assert first.id == second.id  # noqa: S101


@pytest.mark.parametrize(
    "enabled, attributes", [(False, AS_ATTRIBUTES), (True, {"as_owner": "OVH SAS"})]
)
def test_no_autonomous_system(enabled: bool, attributes: dict[str, Any]) -> None:
    """Disabled, or without an ASN, the IP is converted as before."""
    # Given a disabled option or an IP without ASN
    mapper = _mapper(enabled, **attributes)
    # When it is converted
    # Then no autonomous system is created
    assert [obj.type for obj in mapper.to_stix()] == [  # noqa: S101
        "ipv4-addr",
        "indicator",
        "relationship",
    ]


def test_report_ip_autonomous_system_not_linked_to_context() -> None:
    """The autonomous system belongs to the IP, not to the report threats."""
    # Given a report converter with the option enabled
    config = MagicMock(
        indicator_scoring="threat_score",
        indicator_min_verdict="any",
        extended_descriptions=False,
        ioc_tags_as_labels=False,
        ip_link_to_asn=True,
    )
    converter = ConvertToSTIXReport(
        config=config, logger=logging.getLogger(__name__), tlp_level="white"
    )
    ip = GTIIPData(id=IP, type="ip_address", attributes=AS_ATTRIBUTES)
    # When the report IPs are converted
    stix_objects = converter.convert_subentities_to_stix(
        {"ip_addresses": [ip]}, main_entity="report"
    )
    # Then the autonomous system is only the target of 'belongs-to'
    autonomous_system = next(
        obj for obj in stix_objects if obj.type == "autonomous-system"
    )
    targeting = [
        obj.relationship_type
        for obj in stix_objects
        if getattr(obj, "target_ref", None) == autonomous_system.id
    ]
    assert targeting == ["belongs-to"]  # noqa: S101
