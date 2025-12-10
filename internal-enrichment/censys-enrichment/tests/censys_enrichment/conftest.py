import os
import sys
from dataclasses import asdict
from unittest.mock import MagicMock, Mock, patch

import pytest
from censys_platform import (
    Attribute,
    BasicConstraints,
    Certificate,
    CertificateExtensions,
    CertificateParsed,
    CertificatePolicy,
    Coordinates,
    ExtendedKeyUsage,
    Host,
    HostAsset,
    HostAssetWithMatchedServices,
    HostDNS,
    KeyAlgorithm,
    KeyUsage,
    Location,
    ResponseEnvelopeHostAsset,
    ResponseEnvelopeSearchQueryResponse,
    Routing,
    SearchQueryHit,
    SearchQueryResponse,
    Service,
    Signature,
    SubjectKeyInfo,
    V3GlobaldataAssetHostResponse,
    V3GlobaldataSearchQueryResponse,
    ValidityPeriod,
)
from pycti import OpenCTIConnectorHelper
from pytest_mock import MockerFixture

from .factories import DomainNameEnrichmentFactory, HostFactory, Ipv4EnrichmentFactory

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
def fixture_host_ipv4() -> Host:
    return Host(
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
        services=[
            Service(
                banner="HTTP/1.1 301 Moved Permanently",
                cert=Certificate(
                    fingerprint_md5="956f4b8a30ec423d4bbec9ec60df71df",
                    fingerprint_sha1="3ba7e9f806eb30d2f4e3f905e53f07e9acf08e1e",
                    fingerprint_sha256="73b8ed5becf1ba6493d2e2215a42dfdc7877e91e311ff5e59fb43d094871e699",
                    parsed=CertificateParsed(
                        serial_number="123456789",
                        issuer_dn="C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
                        subject_dn="CN=one.one.one.one",
                        signature=Signature(
                            signature_algorithm=KeyAlgorithm(name="SHA256-RSA")
                        ),
                        validity_period=ValidityPeriod(
                            not_before="2025-01-02T00:00:00Z",
                            not_after="2026-01-02T00:00:00Z",
                        ),
                        subject_key_info=SubjectKeyInfo(
                            key_algorithm=KeyAlgorithm(name="ECDSA")
                        ),
                        extensions=CertificateExtensions(
                            key_usage=KeyUsage(),
                            basic_constraints=BasicConstraints(),
                            crl_distribution_points=[
                                "http://crl3.digicert.com/example.crl"
                            ],
                            authority_key_id="748580c066c7df37decfbd2937aa031dbeedcd17",
                            extended_key_usage=ExtendedKeyUsage(),
                            certificate_policies=[
                                CertificatePolicy(
                                    cps=["http://cps.digicert.com/example-cps"],
                                    id="2.23.140.1.2.2",
                                )
                            ],
                        ),
                    ),
                ),
                port=443,
                scan_time="2025-11-03T12:35:48Z",
                software=[
                    Attribute(
                        product="cloudflare_waf",
                        vendor="cloudflare",
                        cpe="cpe:2.3:a:cloudflare:waf:*:*:*:*:*:*:*:*",
                    )
                ],
            )
        ],
    )


@pytest.fixture
def get_host():
    with patch("censys_platform.global_data.GlobalData.get_host") as mock_get_host:
        host = HostFactory()
        result = V3GlobaldataAssetHostResponse(
            headers={},
            result=ResponseEnvelopeHostAsset(
                result=HostAsset(
                    extensions={},
                    resource=host,
                )
            ),
        )
        mock_get_host.return_value = result
        yield host


@pytest.fixture
def ipv4_enrichment_message():
    yield asdict(Ipv4EnrichmentFactory())


@pytest.fixture
def fetch_hosts():
    with patch("censys_platform.global_data.GlobalData.search") as mock_fetch_hosts:
        hosts = HostFactory.create_batch(2)
        result = V3GlobaldataSearchQueryResponse(
            headers={},
            result=ResponseEnvelopeSearchQueryResponse(
                result=SearchQueryResponse(
                    hits=[
                        SearchQueryHit(
                            host_v1=HostAssetWithMatchedServices(
                                extensions={},
                                resource=hosts[0],
                            )
                        ),
                        SearchQueryHit(
                            host_v1=HostAssetWithMatchedServices(
                                extensions={},
                                resource=hosts[1],
                            )
                        ),
                    ],
                    total_hits=2,
                    next_page_token="",
                    query_duration_millis=123,
                    previous_page_token="",
                ),
            ),
        )
        mock_fetch_hosts.return_value = result
        yield hosts


@pytest.fixture
def domain_name_enrichment_message():
    yield asdict(DomainNameEnrichmentFactory())
