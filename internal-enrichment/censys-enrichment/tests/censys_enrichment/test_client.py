"""Tests for the Censys/NVD API client (censys_enrichment.client)."""

from unittest.mock import MagicMock, patch

import pytest
from censys_enrichment.client import Client, EntityHasNoUsableHashError
from censys_platform import (
    CertificateAsset,
    ResponseEnvelopeSearchQueryResponse,
    SearchQueryHit,
    SearchQueryResponse,
    V3GlobaldataSearchQueryResponse,
)

from .factories import CertificateFactory

# =====================
# Test Cases: fetch_certs
# =====================


def test_fetch_certs_raises_without_a_usable_hash() -> None:
    """Test that fetch_certs rejects a hashes dict with no recognized hash key."""
    client = Client(organisation_id="org", token="tok")
    with pytest.raises(EntityHasNoUsableHashError):
        list(client.fetch_certs(hashes={"SHA-512": "deadbeef"}))


@pytest.mark.parametrize(
    "hashes",
    [
        {"MD5": "aaaa"},
        {"SHA-1": "bbbb"},
        {"SHA-256": "cccc"},
        {"MD5": "aaaa", "SHA-1": "bbbb", "SHA-256": "cccc"},
    ],
)
def test_fetch_certs_yields_matching_certificates(hashes: dict[str, str]) -> None:
    """Test that fetch_certs yields certificates for each recognized hash type."""
    cert = CertificateFactory()
    result = V3GlobaldataSearchQueryResponse(
        headers={},
        result=ResponseEnvelopeSearchQueryResponse(
            result=SearchQueryResponse(
                hits=[
                    SearchQueryHit(
                        certificate_v1=CertificateAsset(extensions={}, resource=cert)
                    )
                ],
                total_hits=1,
                next_page_token="",
                query_duration_millis=1,
                previous_page_token="",
            )
        ),
    )
    client = Client(organisation_id="org", token="tok")
    with patch("censys_platform.global_data.GlobalData.search", return_value=result):
        certs = list(client.fetch_certs(hashes=hashes))
    assert certs == [cert]


def test_fetch_certs_skips_hits_without_certificate() -> None:
    """Test that fetch_certs ignores hits that don't carry a certificate_v1 resource."""
    result = V3GlobaldataSearchQueryResponse(
        headers={},
        result=ResponseEnvelopeSearchQueryResponse(
            result=SearchQueryResponse(
                hits=[SearchQueryHit(certificate_v1=None)],
                total_hits=1,
                next_page_token="",
                query_duration_millis=1,
                previous_page_token="",
            )
        ),
    )
    client = Client(organisation_id="org", token="tok")
    with patch("censys_platform.global_data.GlobalData.search", return_value=result):
        certs = list(client.fetch_certs(hashes={"MD5": "aaaa"}))
    assert certs == []


# =====================
# Test Cases: fetch_nvd_data
# =====================


def _nvd_response(**overrides) -> MagicMock:
    """Build a MagicMock response for the NVD API with sensible defaults."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    payload = {
        "vulnerabilities": [
            {"cve": {"descriptions": [], "metrics": {}, "references": []}}
        ]
    }
    payload.update(overrides)
    mock_response.json.return_value = payload
    return mock_response


def test_fetch_nvd_data_returns_none_without_vulnerabilities() -> None:
    """Test that an empty vulnerabilities list yields no NVD data."""
    mock_response = _nvd_response(vulnerabilities=[])
    client = Client(organisation_id="org", token="tok")
    with patch("requests.get", return_value=mock_response):
        result = client.fetch_nvd_data("CVE-2024-0001")
    assert result is None


def test_fetch_nvd_data_returns_none_when_nothing_actionable() -> None:
    """Test that a CVE with no description, severity, score or references returns None."""
    mock_response = _nvd_response()
    client = Client(organisation_id="org", token="tok")
    with patch("requests.get", return_value=mock_response):
        result = client.fetch_nvd_data("CVE-2024-0001")
    assert result is None


def test_fetch_nvd_data_parses_cvss_v2_metrics() -> None:
    """Test that CVSS v2 fields are extracted from the first cvssMetricV2 entry."""
    mock_response = _nvd_response(
        vulnerabilities=[
            {
                "cve": {
                    "descriptions": [],
                    "references": [],
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "cvssData": {
                                    "baseScore": 7.5,
                                    "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                    "accessVector": "NETWORK",
                                    "accessComplexity": "LOW",
                                    "authentication": "NONE",
                                    "confidentialityImpact": "PARTIAL",
                                    "integrityImpact": "PARTIAL",
                                    "availabilityImpact": "PARTIAL",
                                }
                            }
                        ]
                    },
                }
            }
        ]
    )
    client = Client(organisation_id="org", token="tok")
    with patch("requests.get", return_value=mock_response):
        result = client.fetch_nvd_data("CVE-2024-0001")
    assert result is not None
    assert result.cvss_v2_base_score == 7.5
    assert result.cvss_v2_vector_string == "AV:N/AC:L/Au:N/C:P/I:P/A:P"
    assert result.cvss_v2_access_vector == "NETWORK"


def test_fetch_nvd_data_reference_without_tags_falls_back_to_netloc() -> None:
    """Test that a reference lacking tags derives its source name from the URL host."""
    mock_response = _nvd_response(
        vulnerabilities=[
            {
                "cve": {
                    "descriptions": [],
                    "metrics": {},
                    "references": [
                        {"url": "https://example.com/advisory", "tags": []},
                        {"url": "", "tags": ["ignored"]},
                    ],
                }
            }
        ]
    )
    client = Client(organisation_id="org", token="tok")
    with patch("requests.get", return_value=mock_response):
        result = client.fetch_nvd_data("CVE-2024-0001")
    assert result is not None
    assert len(result.references) == 1
    assert result.references[0].source_name == "example.com"


def test_fetch_nvd_data_version_range_start_excluding_end_including() -> None:
    """Test the versionStartExcluding/versionEndIncluding branch of range building."""
    mock_response = _nvd_response(
        vulnerabilities=[
            {
                "cve": {
                    "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
                    "metrics": {},
                    "references": [],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                                            "versionStartExcluding": "1.0",
                                            "versionEndIncluding": "2.0",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    )
    client = Client(organisation_id="org", token="tok")
    with patch("requests.get", return_value=mock_response):
        result = client.fetch_nvd_data("CVE-2024-0001")
    assert result is not None
    assert result.affected_software[0].version_info == "> 1.0, <= 2.0"


def test_fetch_nvd_data_swallows_unexpected_errors() -> None:
    """Test that an unexpected error while fetching NVD data returns None."""
    client = Client(organisation_id="org", token="tok")
    with patch("requests.get", side_effect=RuntimeError("network down")):
        result = client.fetch_nvd_data("CVE-2024-0001")
    assert result is None


def test_fetch_nvd_data_raises_for_status_on_non_403_errors() -> None:
    """Test that a non-403 HTTP error is swallowed via the outer exception handler."""
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = RuntimeError("server error")
    client = Client(organisation_id="org", token="tok")
    with patch("requests.get", return_value=mock_response):
        result = client.fetch_nvd_data("CVE-2024-0001")
    assert result is None
