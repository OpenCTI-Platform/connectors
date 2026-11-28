import json

from tests.conftest import make_vulnerability
from tests.tests_connector.test_cvss_metrics import _build_converter_for_unit


def _ssvc_metrics(exploitation: str, automatable: str, technical_impact: str) -> dict:
    return {
        "ssvcV203": [
            {
                "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                "ssvcData": {
                    "timestamp": "2024-04-17T04:00:13.543064Z",
                    "id": "CVE-2024-3400",
                    "options": [
                        {"exploitation": exploitation},
                        {"automatable": automatable},
                        {"technicalImpact": technical_impact},
                    ],
                    "role": "CISA Coordinator",
                    "version": "2.0.3",
                },
            }
        ]
    }


def test_vulnerability_to_stix2_maps_ssvc_attributes():
    converter = _build_converter_for_unit()
    vulnerability = make_vulnerability("CVE-2024-3400")
    vulnerability["cve"]["metrics"].update(_ssvc_metrics("active", "yes", "total"))

    stix_vulnerability = converter._vulnerability_to_stix2(vulnerability)
    stix_dict = json.loads(stix_vulnerability.serialize())

    assert stix_dict["x_opencti_ssvc_exploitation"] == "active"
    assert stix_dict["x_opencti_ssvc_automatable"] == "yes"
    assert stix_dict["x_opencti_ssvc_technical_impact"] == "total"


def test_vulnerability_to_stix2_translates_poc_exploitation_value():
    """NVD sends 'poc' but the OpenCTI SsvcExploitation enum expects
    'proof_of_concept'."""
    converter = _build_converter_for_unit()
    vulnerability = make_vulnerability("CVE-2024-0001")
    vulnerability["cve"]["metrics"].update(_ssvc_metrics("poc", "no", "partial"))

    stix_vulnerability = converter._vulnerability_to_stix2(vulnerability)
    stix_dict = json.loads(stix_vulnerability.serialize())

    assert stix_dict["x_opencti_ssvc_exploitation"] == "proof_of_concept"
    assert stix_dict["x_opencti_ssvc_automatable"] == "no"
    assert stix_dict["x_opencti_ssvc_technical_impact"] == "partial"


def test_vulnerability_to_stix2_handles_missing_ssvc_block():
    """Not all CVEs have SSVC data; the connector must not fail nor add the
    SSVC properties when the block is absent."""
    converter = _build_converter_for_unit()
    vulnerability = make_vulnerability("CVE-2019-0001")
    # Ensure no ssvcV203 key is present (make_vulnerability does not set it).
    vulnerability["cve"]["metrics"].pop("ssvcV203", None)

    stix_vulnerability = converter._vulnerability_to_stix2(vulnerability)
    stix_dict = json.loads(stix_vulnerability.serialize())

    assert "x_opencti_ssvc_exploitation" not in stix_dict
    assert "x_opencti_ssvc_automatable" not in stix_dict
    assert "x_opencti_ssvc_technical_impact" not in stix_dict
