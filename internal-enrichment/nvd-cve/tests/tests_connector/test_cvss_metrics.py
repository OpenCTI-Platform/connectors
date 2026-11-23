import json

from src.services.converter.vulnerability_to_stix2 import CVEConverter

from tests.conftest import make_vulnerability


def _build_converter_for_unit() -> CVEConverter:
    converter = CVEConverter.__new__(CVEConverter)
    converter.author = CVEConverter._create_author()
    return converter


def test_vulnerability_to_stix2_maps_cvss_30_when_31_absent():
    converter = _build_converter_for_unit()
    vulnerability = make_vulnerability("CVE-2020-1234")

    vulnerability["cve"]["metrics"] = {
        "cvssMetricV30": [
            {
                "type": "Primary",
                "cvssData": {
                    "vectorString": "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
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
    # The exact NVD vector string must be preserved so the CVSS:3.0/ prefix is
    # kept and OpenCTI does not fall back to reconstructing it as CVSS:3.1/.
    assert (
        stix_dict["x_opencti_cvss_vector_string"]
        == "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"
    )


def test_vulnerability_to_stix2_prefers_cvss_31_over_30():
    converter = _build_converter_for_unit()
    vulnerability = make_vulnerability("CVE-2020-9999")

    vulnerability["cve"]["metrics"] = {
        "cvssMetricV31": [
            {
                "type": "Primary",
                "cvssData": {
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
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
                    "vectorString": "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L",
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
    assert (
        stix_dict["x_opencti_cvss_vector_string"]
        == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    )


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


def test_converter_marks_nvd_objects_tlp_clear():
    from src.services.converter.vulnerability_to_stix2 import nvd_marking

    from tests.conftest import make_cpe_name

    clear_id = nvd_marking().id
    assert clear_id == "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    converter = _build_converter_for_unit()
    vulnerability = converter._vulnerability_to_stix2(
        make_vulnerability("CVE-2024-3400")
    )
    placeholder = converter._placeholder_vulnerability_to_stix2("CVE-2024-3401")
    software = converter._create_software(make_cpe_name())
    relationship = converter._create_relationship(software.id, vulnerability.id, "has")
    for obj in (vulnerability, placeholder, software, relationship):
        assert obj.object_marking_refs == [clear_id]
