import json
from unittest.mock import MagicMock

from src.services.client.vulnerability import CVEVulnerability
from src.services.converter.vulnerability_to_stix2 import CVEConverter
from src.services.utils.rate_limiter import AsyncRateLimiter

from tests.conftest import make_vulnerability


def _build_cve_vulnerability_client() -> CVEVulnerability:
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    return CVEVulnerability(
        api_key="fake-key",
        helper=helper,
        header="test/1.0",
        rate_limiter=AsyncRateLimiter(),
        base_url="https://example.test",
    )


def _build_converter_for_unit() -> CVEConverter:
    converter = CVEConverter.__new__(CVEConverter)
    converter.author = CVEConverter._create_author()
    return converter


def test_filter_cvss_includes_cvss_metric_v30():
    client = _build_cve_vulnerability_client()
    vulnerabilities = [
        {
            "cve": {
                "id": "CVE-2020-0001",
                "metrics": {"cvssMetricV30": [{"type": "Primary", "cvssData": {}}]},
            }
        },
        {
            "cve": {
                "id": "CVE-2020-0002",
                "metrics": {"unsupportedMetric": [{"foo": "bar"}]},
            }
        },
    ]

    filtered = client._filter_cvss(vulnerabilities)

    assert len(filtered) == 1
    assert filtered[0]["cve"]["id"] == "CVE-2020-0001"


def test_vulnerability_to_stix2_maps_cvss_30_when_31_absent():
    converter = _build_converter_for_unit()
    vulnerability = make_vulnerability("CVE-2020-1234")

    vulnerability["cve"]["metrics"] = {
        "cvssMetricV30": [
            {
                "type": "Primary",
                "cvssData": {
                    "baseScore": 5.2,
                    "baseSeverity": "MEDIUM",
                    "attackVector": "NETWORK",
                    "attackComplexity": "HIGH",
                    "privilegesRequired": "LOW",
                    "userInteraction": "REQUIRED",
                    "scope": "UNCHANGED",
                    "confidentialityImpact": "LOW",
                    "integrityImpact": "LOW",
                    "availabilityImpact": "NONE",
                },
            }
        ]
    }

    stix_vulnerability = converter._vulnerability_to_stix2(vulnerability)
    stix_dict = json.loads(stix_vulnerability.serialize())

    assert stix_dict["x_opencti_base_score"] == 5.2
    assert stix_dict["x_opencti_base_severity"] == "MEDIUM"
    assert stix_dict["x_opencti_cvss_scope"] == "UNCHANGED"


def test_vulnerability_to_stix2_prefers_cvss_31_over_30():
    converter = _build_converter_for_unit()
    vulnerability = make_vulnerability("CVE-2020-9999")

    vulnerability["cve"]["metrics"] = {
        "cvssMetricV31": [
            {
                "type": "Primary",
                "cvssData": {
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                    "attackVector": "NETWORK",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "NONE",
                    "userInteraction": "NONE",
                    "scope": "CHANGED",
                    "confidentialityImpact": "HIGH",
                    "integrityImpact": "HIGH",
                    "availabilityImpact": "HIGH",
                },
            }
        ],
        "cvssMetricV30": [
            {
                "type": "Primary",
                "cvssData": {
                    "baseScore": 4.3,
                    "baseSeverity": "MEDIUM",
                    "attackVector": "LOCAL",
                    "attackComplexity": "HIGH",
                    "privilegesRequired": "LOW",
                    "userInteraction": "REQUIRED",
                    "scope": "UNCHANGED",
                    "confidentialityImpact": "LOW",
                    "integrityImpact": "LOW",
                    "availabilityImpact": "LOW",
                },
            }
        ],
    }

    stix_vulnerability = converter._vulnerability_to_stix2(vulnerability)
    stix_dict = json.loads(stix_vulnerability.serialize())

    assert stix_dict["x_opencti_base_score"] == 9.8
    assert stix_dict["x_opencti_base_severity"] == "CRITICAL"
    assert stix_dict["x_opencti_cvss_scope"] == "CHANGED"


def test_vulnerability_to_stix2_cvss_30_secondary_selected_when_no_primary():
    """When cvssMetricV30 has multiple entries but none is Primary, the first
    Secondary entry should be selected (covers the elif branch)."""
    converter = _build_converter_for_unit()
    vulnerability = make_vulnerability("CVE-2018-5678")

    vulnerability["cve"]["metrics"] = {
        "cvssMetricV30": [
            {
                "type": "Secondary",
                "cvssData": {
                    "baseScore": 6.1,
                    "baseSeverity": "MEDIUM",
                    "attackVector": "NETWORK",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "NONE",
                    "userInteraction": "REQUIRED",
                    "scope": "CHANGED",
                    "confidentialityImpact": "LOW",
                    "integrityImpact": "LOW",
                    "availabilityImpact": "NONE",
                },
            },
            {
                "type": "Secondary",
                "cvssData": {
                    "baseScore": 3.5,
                    "baseSeverity": "LOW",
                    "attackVector": "LOCAL",
                    "attackComplexity": "HIGH",
                    "privilegesRequired": "LOW",
                    "userInteraction": "REQUIRED",
                    "scope": "UNCHANGED",
                    "confidentialityImpact": "NONE",
                    "integrityImpact": "LOW",
                    "availabilityImpact": "NONE",
                },
            },
        ]
    }

    stix_vulnerability = converter._vulnerability_to_stix2(vulnerability)
    stix_dict = json.loads(stix_vulnerability.serialize())

    # First Secondary entry should be selected
    assert stix_dict["x_opencti_base_score"] == 6.1
    assert stix_dict["x_opencti_base_severity"] == "MEDIUM"
