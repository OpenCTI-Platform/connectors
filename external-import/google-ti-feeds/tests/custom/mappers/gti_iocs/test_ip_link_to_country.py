"""Tests for the country of IP IOCs (GTI_IP_LINK_TO_COUNTRY)."""

import logging
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from connector.src.custom.convert_to_stix.report.convert_to_stix_report import (
    ConvertToSTIXReport,
)
from connector.src.custom.mappers.gti_iocs.gti_ip_to_stix_ip import (
    GTIIPToSTIXIP,
    country_from_code,
)
from connector.src.custom.models.gti.gti_ip_addresses_model import GTIIPData
from pycti import Location  # type: ignore[import-untyped]
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

IP = "147.135.242.186"
NETWORK = {
    "country": "FR",
    "continent": "EU",
    "asn": 16276,
    "as_owner": "OVH SAS",
    "regional_internet_registry": "RIPE NCC",
}


def _mapper(**options: Any) -> GTIIPToSTIXIP:
    organization = Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )
    marking = MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )
    attributes = {**NETWORK, **options.pop("attributes", {})}
    ip = GTIIPData(id=IP, type="ip_address", attributes=attributes)
    return GTIIPToSTIXIP(ip, organization, marking, **options)


@pytest.mark.parametrize(
    "code, expected",
    [
        ("FR", ("France", ["French Republic", "FR", "FRA"])),
        ("TW", ("Taiwan", ["Taiwan, Province of China", "TW", "TWN"])),
        ("ZZ", None),
        (None, None),
        ("", None),
    ],
)
def test_country_from_code(
    code: str | None, expected: tuple[str, list[str]] | None
) -> None:
    """ISO codes give the common country name, other names and codes as aliases."""
    # Given an ISO 3166-1 alpha-2 code
    # When it is resolved
    # Then the name and aliases match, unknown codes give None
    assert country_from_code(code) == expected  # noqa: S101


def test_ip_located_at_its_country() -> None:
    """When enabled, the IP is located at its country, identified by name."""
    # Given an IP in France
    mapper = _mapper(ip_link_to_country=True)
    # When it is converted
    observable, _, _, country, located_at = mapper.to_stix()
    # Then the country matches the OpenCTI country ID and the IP is located at it
    assert country.id == Location.generate_id("France", "Country")  # noqa: S101
    assert country.country == "FR"  # noqa: S101
    assert country.x_opencti_location_type == "Country"  # noqa: S101
    assert located_at.relationship_type == "located-at"  # noqa: S101
    assert located_at.source_ref == observable.id  # noqa: S101
    assert located_at.target_ref == country.id  # noqa: S101


def test_unknown_country_code_is_skipped() -> None:
    """An unknown country code creates no location."""
    # Given an IP with an unknown country code
    mapper = _mapper(ip_link_to_country=True, attributes={"country": "ZZ"})
    # When it is converted
    # Then no location is created
    assert "location" not in [obj.type for obj in mapper.to_stix()]  # noqa: S101


@pytest.mark.parametrize(
    "options, expected",
    [
        (
            {},
            "- Country: FR\n- Continent: EU\n- Autonomous system: AS16276 (OVH SAS)\n"
            "- Regional internet registry: RIPE NCC",
        ),
        (
            {"ip_link_to_country": True},
            "- Continent: EU\n- Autonomous system: AS16276 (OVH SAS)\n"
            "- Regional internet registry: RIPE NCC",
        ),
        ({"ip_link_to_asn": True}, "- Country: FR\n- Continent: EU"),
        ({"ip_link_to_asn": True, "ip_link_to_country": True}, "- Continent: EU"),
    ],
)
def test_linked_fields_left_out_of_description(
    options: dict[str, bool], expected: str
) -> None:
    """Fields imported as linked objects are not repeated in the description."""
    # Given an IP mapper with extended descriptions and link options
    mapper = _mapper(extended_descriptions=True, **options)
    # When it is converted
    observable, indicator = mapper.to_stix()[:2]
    # Then only the unlinked fields are described
    description = "**GTI network details**\n\n" + expected
    assert indicator.description == description  # noqa: S101
    assert observable.x_opencti_description == description  # noqa: S101


def test_unknown_country_stays_in_description() -> None:
    """A country code that cannot be linked stays in the description."""
    # Given an IP with an unknown country code and the country link enabled
    mapper = _mapper(
        extended_descriptions=True,
        ip_link_to_country=True,
        attributes={"country": "ZZ"},
    )
    # When it is converted
    # Then the code is described
    assert "- Country: ZZ" in mapper.to_stix()[1].description  # noqa: S101


def test_report_ip_country_not_linked_to_context() -> None:
    """The country belongs to the IP, not to the report threats."""
    # Given a report converter with the option enabled
    config = MagicMock(
        indicator_scoring="threat_score",
        indicator_min_verdict="any",
        extended_descriptions=False,
        ioc_tags_as_labels=False,
        ip_link_to_asn=False,
        ip_link_to_country=True,
    )
    converter = ConvertToSTIXReport(
        config=config, logger=logging.getLogger(__name__), tlp_level="white"
    )
    ip = GTIIPData(id=IP, type="ip_address", attributes=NETWORK)
    # When the report IPs are converted
    stix_objects = converter.convert_subentities_to_stix(
        {"ip_addresses": [ip]}, main_entity="report"
    )
    # Then the country is only the target of 'located-at'
    country = next(obj for obj in stix_objects if obj.type == "location")
    targeting = [
        obj.relationship_type
        for obj in stix_objects
        if getattr(obj, "target_ref", None) == country.id
    ]
    assert targeting == ["located-at"]  # noqa: S101
