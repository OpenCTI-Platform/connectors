# pragma: no cover  # do not compute coverage on test files
"""Offer tests for observations OpenCTI entities."""

import pytest
from connectors_sdk.models.octi._common import BaseIdentifiedEntity
from connectors_sdk.models.octi.enums import (
    CvssSeverity,
    ImplementationLanguage,
    MalwareCapability,
    MalwareType,
    ProcessorArchitecture,
)
from connectors_sdk.models.octi.knowledge.arsenal import Malware, Vulnerability
from pydantic import ValidationError
from stix2.v21 import Malware as Stix2Malware
from stix2.v21 import Vulnerability as Stix2Vulnerability

### MALWARE


def test_malware_is_a_base_identified_entity():
    """Test that Malware is a BaseIdentifiedEntity."""
    # Given the Malware class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Malware, BaseIdentifiedEntity)


def test_malware_class_should_not_accept_invalid_input():
    """Test that Malware class should not accept invalid input."""
    # Given: An invalid input data for Malware
    input_data = {
        "name": "Test Malware",
        "invalid_key": "invalid_value",
    }
    # When validating the malware
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Malware.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_malware_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Malware to_stix2_object method returns a valid STIX2.1 Malware."""
    # Given: A valid Malware instance
    malware = Malware(
        name="Test Malware",
        description="Test description",
        aliases=["alias_1", "alias_2"],
        is_family=False,
        types=[MalwareType.ADWARE],
        first_seen="2023-01-01T00:00:00+00:00",
        last_seen="2024-01-01T00:00:00+00:00",
        architecture_execution_envs=[ProcessorArchitecture.ALPHA],
        implementation_languages=[ImplementationLanguage.APPLESCRIPT],
        kill_chain_phases=[{"chain_name": "test", "phase_name": "pre-attack"}],
        capabilities=[MalwareCapability.ACCESSES_REMOTE_MACHINES],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = malware.to_stix2_object()
    # Then: A valid STIX2.1 Malware is returned
    assert isinstance(stix2_obj, Stix2Malware)


### VULNERABILITY


def test_vulnerability_is_a_base_identified_entity():
    """Test that Vulnerability is a BaseIdentifiedEntity."""
    # Given the Vulnerability class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Vulnerability, BaseIdentifiedEntity)


def test_vulnerability_class_should_not_accept_invalid_input():
    """Test that Vulnerability class should not accept invalid input."""
    # Given: An invalid input data for Vulnerability
    input_data = {
        "name": "CVE-2025-1234",
        "invalid_key": "invalid_value",
    }
    # When validating the vulnerability
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Vulnerability.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_vulnerability_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Vulnerability to_stix2_object method returns a valid STIX2.1 Vulnerability."""
    # Given: A valid Vulnerability instance
    vulnerability = Vulnerability(
        name="CVE-2025-1234",
        description="Test description",
        aliases=["alias_1", "alias_2"],
        epss_score=0.5,
        epss_percentile=0.5,
        is_cisa_kev=False,
        cvss_v2_vector_string="Dummy string",
        cvss_v2_base_score=9.0,
        cvss_v2_access_vector="Local",
        cvss_v2_access_complexity="High",
        cvss_v2_authentication="Multiple",
        cvss_v2_confidentiality_impact="None",
        cvss_v2_integrity_impact="None",
        cvss_v2_availability_impact="None",
        cvss_v2_exploitability="Unproven",
        cvss_v3_vector_string="Dummy string",
        cvss_v3_base_score=9.0,
        cvss_v3_base_severity=CvssSeverity.CRITICAL,
        cvss_v3_attack_vector="Network",
        cvss_v3_attack_complexity="Low",
        cvss_v3_privileges_required="None",
        cvss_v3_user_interaction="None",
        cvss_v3_integrity_impact="High",
        cvss_v3_availability_impact="High",
        cvss_v3_confidentiality_impact="High",
        cvss_v3_scope="Unchanged",
        cvss_v3_exploit_code_maturity="Not Defined",
        cvss_v4_vector_string="Dummy string",
        cvss_v4_base_score=9.0,
        cvss_v4_base_severity=CvssSeverity.CRITICAL,
        cvss_v4_attack_vector="Network",
        cvss_v4_attack_complexity="Low",
        cvss_v4_attack_requirements="None",
        cvss_v4_privileges_required="None",
        cvss_v4_user_interaction="None",
        cvss_v4_vs_confidentiality_impact="High",
        cvss_v4_ss_confidentiality_impact="High",
        cvss_v4_vs_integrity_impact="High",
        cvss_v4_ss_integrity_impact="High",
        cvss_v4_vs_availability_impact="High",
        cvss_v4_ss_availability_impact="High",
        cvss_v4_exploit_maturity="Not Defined",
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = vulnerability.to_stix2_object()
    # Then: A valid STIX2.1 Vulnerability is returned
    assert isinstance(stix2_obj, Stix2Vulnerability)
