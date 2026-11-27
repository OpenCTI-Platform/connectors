"""Tests for the network details of IP descriptions (GTI_EXTENDED_DESCRIPTIONS)."""

import logging
from unittest.mock import MagicMock
from uuid import uuid4

from connector.src.custom.convert_to_stix.indicator.convert_to_stix_indicator import (
    ConvertToSTIXIndicator,
)
from connector.src.custom.mappers.gti_iocs.gti_ip_to_stix_ip import GTIIPToSTIXIP
from connector.src.custom.mappers.gti_iocs.ioc_assessment import (
    build_ioc_description,
    network_details_section,
)
from connector.src.custom.models.gti.gti_domain_model import DomainModel
from connector.src.custom.models.gti.gti_ioc_delta_model import (
    IOCDeltaAttributes,
    IOCDeltaEntry,
)
from connector.src.custom.models.gti.gti_ip_addresses_model import (
    GTIIPData,
    IPModel,
)
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

IP = "147.135.242.186"
NETWORK = {
    "country": "FR",
    "continent": "EU",
    "asn": 16276,
    "as_owner": "OVH SAS",
    "network": "147.135.0.0/16",
    "regional_internet_registry": "RIPE NCC",
}
NETWORK_DETAILS = (
    "**GTI network details**\n\n"
    "- Country: FR\n"
    "- Continent: EU\n"
    "- Autonomous system: AS16276 (OVH SAS)\n"
    "- Network: 147.135.0.0/16\n"
    "- Regional internet registry: RIPE NCC"
)


def test_network_details_section() -> None:
    """IP network attributes are listed, missing ones skipped."""
    # Given IP attributes, full and partial
    # When the network details are built
    # Then the available attributes are listed
    assert network_details_section(IPModel(**NETWORK)) == NETWORK_DETAILS  # noqa: S101
    assert network_details_section(IPModel(asn=16276)) == (  # noqa: S101
        "**GTI network details**\n\n- Autonomous system: AS16276"
    )
    assert network_details_section(DomainModel()) is None  # noqa: S101


def test_build_ioc_description_appends_network_details() -> None:
    """Network details follow the GTI assessment."""
    # Given IP attributes with a verdict
    attributes = IPModel(
        **NETWORK, gti_assessment={"verdict": {"value": "VERDICT_MALICIOUS"}}
    )
    # When the description is built
    # Then the assessment comes first
    assert build_ioc_description(attributes) == (  # noqa: S101
        "**GTI assessment**\n\n- Verdict: Malicious\n\n" + NETWORK_DETAILS
    )
    assert build_ioc_description(None) is None  # noqa: S101


def test_collection_ip_description() -> None:
    """Collection IP indicators and observables carry the network details."""
    # Given an IP mapper with extended descriptions
    organization = Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )
    marking = MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )
    ip = GTIIPData(id=IP, type="ip_address", attributes=IPModel(**NETWORK))
    mapper = GTIIPToSTIXIP(ip, organization, marking, extended_descriptions=True)
    # When it is converted
    observable, indicator, _ = mapper.to_stix()
    # Then both carry the network details
    assert indicator.description == NETWORK_DETAILS  # noqa: S101
    assert observable.x_opencti_description == NETWORK_DETAILS  # noqa: S101


def test_delta_ip_description() -> None:
    """IOC delta IP indicators carry the network details."""
    # Given a delta converter with extended descriptions and an IP entry
    config = MagicMock(
        indicator_scoring="threat_score",
        extended_descriptions=True,
        ioc_tags_as_labels=False,
        indicator_subentities=[],
    )
    converter = ConvertToSTIXIndicator(
        config=config, logger=logging.getLogger(__name__), tlp_level="white"
    )
    entry = IOCDeltaEntry(
        id=IP, type="ip_address", attributes=IOCDeltaAttributes(**NETWORK)
    )
    # When it is converted
    indicator = converter._convert_ip(entry)
    # Then the description lists the network details
    assert indicator is not None  # noqa: S101
    assert indicator.description == NETWORK_DETAILS  # noqa: S101
