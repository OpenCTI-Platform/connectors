# pragma: no cover # Do not compute coverage on test files
"""Offer tests for the <Provider><Payload>Converter naming convention."""

import pytest
from connectors_sdk.converters import AbstractConverter
from connectors_sdk.converters.crowdstrike import (
    CrowdStrikeActorConverter,
    CrowdStrikeLocationConverter,
    CrowdStrikeReportPdfConverter,
    CrowdStrikeSectorConverter,
)
from connectors_sdk.converters.ransomwarelive import RansomwareLiveVictimConverter
from connectors_sdk.converters.shodan_internetdb import ShodanInternetDbHostConverter
from connectors_sdk.converters.vulnerability_lookup import (
    VulnerabilityLookupCveConverter,
)
from connectors_sdk.converters.whoisfreaks import WhoisFreaksThreatFeedConverter


@pytest.mark.parametrize(
    ("converter", "provider", "payload"),
    [
        (CrowdStrikeActorConverter, "CrowdStrike", "Actor"),
        (CrowdStrikeLocationConverter, "CrowdStrike", "Location"),
        (CrowdStrikeReportPdfConverter, "CrowdStrike", "ReportPdf"),
        (CrowdStrikeSectorConverter, "CrowdStrike", "Sector"),
        (RansomwareLiveVictimConverter, "RansomwareLive", "Victim"),
        (ShodanInternetDbHostConverter, "ShodanInternetDb", "Host"),
        (VulnerabilityLookupCveConverter, "VulnerabilityLookup", "Cve"),
        (WhoisFreaksThreatFeedConverter, "WhoisFreaks", "ThreatFeed"),
    ],
)
def test_converter_name(converter: type, provider: str, payload: str) -> None:
    """Test that each converter is named <Provider><Payload>Converter."""
    assert issubclass(converter, AbstractConverter)
    assert converter.__name__ == f"{provider}{payload}Converter"
