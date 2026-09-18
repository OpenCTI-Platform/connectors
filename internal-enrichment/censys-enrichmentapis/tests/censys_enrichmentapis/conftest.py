import os
import sys
from dataclasses import asdict
from unittest.mock import MagicMock, Mock, patch

import pytest
from censys_platform import (
    Coordinates,
    HostDNS,
    HostEnrichment,
    HostEnrichmentService,
    Label,
    Location,
    Routing,
)
from pycti import OpenCTIConnectorHelper
from pytest_mock import MockerFixture

from .factories import DomainNameEnrichmentFactory, Ipv4EnrichmentFactory

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture(name="mock_config")
def fixture_mock_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENCTI_URL", "http://test")
    monkeypatch.setenv("OPENCTI_TOKEN", "opencti-token")
    monkeypatch.setenv("CENSYS_ENRICHMENT_ORGANISATION_ID", "censys-organisation_id")
    monkeypatch.setenv("CENSYS_ENRICHMENT_TOKEN", "censys-token")


@pytest.fixture(name="mocked_helper")
def fixture_mocked_helper(mocker: MockerFixture) -> Mock:
    mocked_helper = mocker.patch("pycti.OpenCTIConnectorHelper")
    mocked_helper.stix2_create_bundle = MagicMock(
        side_effect=OpenCTIConnectorHelper.stix2_create_bundle
    )
    mocked_helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp
    return mocked_helper


@pytest.fixture(name="host_ipv4")
def fixture_host_ipv4() -> HostEnrichment:
    return HostEnrichment(
        ip="1.1.1.1",
        location=Location(
            city="Brisbane",
            continent="Oceania",
            coordinates=Coordinates(latitude=-27.47, longitude=153.02),
            country="Australia",
            province="Queensland",
        ),
        dns=HostDNS(
            names=["guestcontroller.sa.gov.au", "matrix.cyops.cloud"],
        ),
        autonomous_system=Routing(
            asn=13335,
            bgp_prefix="1.1.1.0/24",
            country_code="US",
            description="CLOUDFLARENET",
            name="CLOUDFLARENET",
        ),
        labels=[
            Label(value="BULLETPROOF"),
            Label(value="BULLETPROOF"),
            Label(value=""),
        ],
        services=[
            HostEnrichmentService(
                port=443,
                scan_time="2025-11-03T12:35:48Z",
                labels=[Label(value="REMOTE_ACCESS")],
            )
        ],
    )


@pytest.fixture
def get_host():
    with patch(
        "censys_platform.global_data.GlobalData.get_host_enrichment"
    ) as mock_get_host_enrichment:
        host = HostEnrichment(
            ip="1.1.1.1",
            location=Location(
                city="Brisbane",
                continent="Oceania",
                coordinates=Coordinates(latitude=-27.47, longitude=153.02),
                country="Australia",
                province="Queensland",
            ),
            dns=HostDNS(
                names=["guestcontroller.sa.gov.au", "matrix.cyops.cloud"],
            ),
            autonomous_system=Routing(
                asn=13335,
                bgp_prefix="1.1.1.0/24",
                country_code="US",
                description="CLOUDFLARENET",
                name="CLOUDFLARENET",
            ),
            labels=[
                Label(value="BULLETPROOF"),
                Label(value="BULLETPROOF"),
                Label(value=""),
            ],
            services=[
                HostEnrichmentService(
                    port=443,
                    scan_time="2025-11-03T12:35:48Z",
                    labels=[Label(value="REMOTE_ACCESS")],
                )
            ],
        )
        mock_result = MagicMock()
        mock_result.result.result.resource = host
        mock_get_host_enrichment.return_value = mock_result
        yield host


@pytest.fixture
def ipv4_enrichment_message():
    yield asdict(Ipv4EnrichmentFactory())


@pytest.fixture
def domain_name_enrichment_message():
    yield asdict(DomainNameEnrichmentFactory())
