"""Tests for the GTI page links of IOC indicators."""

import logging
from typing import Any
from unittest.mock import MagicMock

import pytest
from connector.src.custom.convert_to_stix.report.convert_to_stix_report import (
    ConvertToSTIXReport,
)
from connector.src.custom.mappers.gti_iocs.gti_links import (
    gti_external_reference,
    gti_gui_url,
)
from connector.src.custom.models.gti.gti_domain_model import GTIDomainData
from connector.src.custom.models.gti.gti_file_model import GTIFileData
from connector.src.custom.models.gti.gti_ip_addresses_model import GTIIPData
from connector.src.custom.models.gti.gti_url_model import GTIURLData

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
URL_ID = "1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31"


@pytest.mark.parametrize(
    "ioc_type, ioc_id, name, expected",
    [
        (
            "file",
            SHA256,
            None,
            {
                "source_name": f"[GTI] File {SHA256}",
                "description": "Google Threat Intelligence File Link",
                "url": f"https://www.virustotal.com/gui/file/{SHA256}",
            },
        ),
        (
            "ip_address",
            "1.2.3.4",
            None,
            {
                "source_name": "[GTI] IP 1.2.3.4",
                "description": "Google Threat Intelligence IP Link",
                "url": "https://www.virustotal.com/gui/ip-address/1.2.3.4",
            },
        ),
        (
            "url",
            URL_ID,
            "https://example.com/",
            {
                "source_name": "[GTI] URL https://example.com/",
                "description": "Google Threat Intelligence URL Link",
                "url": f"https://www.virustotal.com/gui/url/{URL_ID}",
            },
        ),
    ],
)
def test_gti_external_reference(
    ioc_type: str, ioc_id: str, name: str | None, expected: dict[str, str]
) -> None:
    """The reference points at the GTI page of the IOC type."""
    # Given an IOC
    # When its GTI reference is built
    # Then it links to the GTI page
    assert gti_external_reference(ioc_type, ioc_id, name) == expected  # noqa: S101


@pytest.mark.parametrize(
    "subentity_type, entity, expected_url",
    [
        (
            "domains",
            GTIDomainData(id="example.com", type="domain"),
            "https://www.virustotal.com/gui/domain/example.com",
        ),
        (
            "files",
            GTIFileData(id=SHA256, type="file", attributes={"sha256": SHA256}),
            f"https://www.virustotal.com/gui/file/{SHA256}",
        ),
        (
            "ip_addresses",
            GTIIPData(id="1.2.3.4", type="ip_address"),
            "https://www.virustotal.com/gui/ip-address/1.2.3.4",
        ),
        (
            "urls",
            GTIURLData(
                id=URL_ID, type="url", attributes={"url": "https://example.com/"}
            ),
            f"https://www.virustotal.com/gui/url/{URL_ID}",
        ),
    ],
)
def test_collection_indicators_link_to_gti(
    subentity_type: str, entity: Any, expected_url: str
) -> None:
    """Indicators of collection IOCs link to their GTI page."""
    # Given a report sub-entity IOC
    converter = ConvertToSTIXReport(
        config=MagicMock(indicator_scoring="threat_score", extended_descriptions=False),
        logger=logging.getLogger(__name__),
        tlp_level="white",
    )
    # When it is converted
    stix_objects = converter.convert_subentities_to_stix(
        {subentity_type: [entity]}, main_entity="report"
    )
    # Then its indicator references the GTI page
    indicator = next(obj for obj in stix_objects if obj.type == "indicator")
    assert [ref.url for ref in indicator.external_references] == [  # noqa: S101
        expected_url
    ]


@pytest.mark.parametrize(
    "object_type, object_id, expected",
    [
        ("collection", "apt1", "https://www.virustotal.com/gui/collection/apt1"),
        ("ip_address", "1.2.3.4", "https://www.virustotal.com/gui/ip-address/1.2.3.4"),
        ("unknown", "x", None),
        ("file", None, None),
        (None, "x", None),
    ],
)
def test_gti_gui_url(
    object_type: str | None, object_id: str | None, expected: str | None
) -> None:
    """Known object types link to their GTI page."""
    # Given a GTI object type and id
    # When the GTI URL is built
    # Then it matches the GUI path, or is None
    assert gti_gui_url(object_type, object_id) == expected  # noqa: S101
