"""Module to test the STIX 2.1 Common Data Types (CDTs)."""

import pytest
from connector.src.stix.v21.models.cdts.external_reference_model import (
    ExternalReferenceModel,
)
from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.stix.v21.models.ovs.hashing_algorithm_ov_enums import HashAlgorithmOV
from pydantic import ValidationError

# =====================
# Test Cases for KillChainPhaseModel
# =====================


def test_kill_chain_phase_valid():
    """Test valid KillChainPhaseModel creation."""
    # Given: Valid kill chain phase data
    phase_data = {
        "kill_chain_name": "mitre-attack",
        "phase_name": "initial-access",
    }

    # When: Creating a model with the data
    phase = KillChainPhaseModel(**phase_data)

    # Then: The model should have the expected values
    assert phase.kill_chain_name == "mitre-attack"  # noqa: S101
    assert phase.phase_name == "initial-access"  # noqa: S101


def test_kill_chain_phase_invalid_uppercase():
    """Test that uppercase kill chain names are rejected."""
    # Given: Invalid kill chain phase data with uppercase characters
    invalid_data = {
        "kill_chain_name": "MITRE-ATTACK",
        "phase_name": "initial-access",
    }

    # When/Then: Creating a model should raise a validation error
    with pytest.raises(ValidationError) as excinfo:
        KillChainPhaseModel(**invalid_data)

    assert "must be lowercase" in str(excinfo.value)  # noqa: S101


def test_kill_chain_phase_invalid_spaces():
    """Test that kill chain names with spaces are rejected."""
    # Given: Invalid kill chain phase data with spaces
    invalid_data = {
        "kill_chain_name": "mitre attack",
        "phase_name": "initial access",
    }

    # When/Then: Creating a model should raise a validation error
    with pytest.raises(ValidationError) as excinfo:
        KillChainPhaseModel(**invalid_data)

    assert "must be lowercase and use hyphens" in str(excinfo.value)  # noqa: S101


def test_kill_chain_phase_invalid_underscores():
    """Test that kill chain names with underscores are rejected."""
    # Given: Invalid kill chain phase data with underscores
    invalid_data = {
        "kill_chain_name": "mitre_attack",
        "phase_name": "initial_access",
    }

    # When/Then: Creating a model should raise a validation error
    with pytest.raises(ValidationError) as excinfo:
        KillChainPhaseModel(**invalid_data)

    assert "must be lowercase and use hyphens" in str(excinfo.value)  # noqa: S101


# =====================
# Test Cases for ExternalReferenceModel
# =====================


def test_external_reference_basic():
    """Test basic ExternalReferenceModel creation with only required fields."""
    # Given: Minimal external reference data with only required fields
    reference_data = {
        "source_name": "MITRE ATT&CK",
    }

    # When: Creating a model with the data
    reference = ExternalReferenceModel(**reference_data)

    # Then: The model should have the expected values
    assert reference.source_name == "MITRE ATT&CK"  # noqa: S101
    assert reference.description is None  # noqa: S101
    assert reference.url is None  # noqa: S101
    assert reference.hashes is None  # noqa: S101
    assert reference.external_id is None  # noqa: S101


def test_external_reference_all_fields():
    """Test ExternalReferenceModel creation with all fields."""
    # Given: Complete external reference data with all fields
    reference_data = {
        "source_name": "MITRE ATT&CK",
        "description": "MITRE ATT&CK Framework",
        "url": "https://attack.mitre.org/techniques/T1566",
        "external_id": "T1566",
        "hashes": {
            HashAlgorithmOV.SHA256: "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f"
        },
    }

    # When: Creating a model with the data
    reference = ExternalReferenceModel(**reference_data)

    # Then: The model should have the expected values
    assert reference.source_name == "MITRE ATT&CK"  # noqa: S101
    assert reference.description == "MITRE ATT&CK Framework"  # noqa: S101
    assert reference.url == "https://attack.mitre.org/techniques/T1566"  # noqa: S101
    assert reference.external_id == "T1566"  # noqa: S101
    assert (  # noqa: S101
        reference.hashes[HashAlgorithmOV.SHA256]
        == "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f"
    )


def test_external_reference_missing_required_field():
    """Test that missing required fields raise validation errors."""
    # Given: External reference data without the required source_name field
    invalid_data = {
        "url": "https://attack.mitre.org/techniques/T1566",
        "external_id": "T1566",
    }

    # When/Then: Creating a model should raise a validation error
    with pytest.raises(ValidationError) as excinfo:
        ExternalReferenceModel(**invalid_data)

    assert "source_name" in str(excinfo.value)  # noqa: S101


def test_external_reference_serialization():
    """Test that ExternalReferenceModel can be serialized to dict."""
    # Given: An external reference model with all fields
    reference = ExternalReferenceModel(
        source_name="MITRE ATT&CK",
        description="MITRE ATT&CK Framework",
        url="https://attack.mitre.org/techniques/T1566",
        external_id="T1566",
        hashes={
            HashAlgorithmOV.SHA256: "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f"
        },
    )

    # When: Serializing the model to a dict
    serialized = reference.model_dump()

    # Then: The dict should have the expected key-value pairs
    assert serialized["source_name"] == "MITRE ATT&CK"  # noqa: S101
    assert serialized["description"] == "MITRE ATT&CK Framework"  # noqa: S101
    assert (  # noqa: S101
        serialized["url"] == "https://attack.mitre.org/techniques/T1566"
    )
    assert serialized["external_id"] == "T1566"  # noqa: S101
    assert HashAlgorithmOV.SHA256 in serialized["hashes"]  # noqa: S101


def test_external_reference_hash_enum_values():
    """Test that hash algorithms are properly handled as enum values."""
    # Given: An external reference with hashes using enum keys
    reference = ExternalReferenceModel(
        source_name="Test Source",
        hashes={
            HashAlgorithmOV.MD5: "5eb63bbbe01eeed093cb22bb8f5acdc3",
            HashAlgorithmOV.SHA1: "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
        },
    )

    # When: Serializing the model to a dict
    serialized = reference.model_dump()

    # Then: The hashes should be properly mapped with enum values as strings
    assert (  # noqa: S101
        serialized["hashes"]["MD5"] == "5eb63bbbe01eeed093cb22bb8f5acdc3"
    )
    assert (  # noqa: S101
        serialized["hashes"]["SHA-1"] == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    )

    # And: The original model should preserve enum keys
    assert (  # noqa: S101
        reference.hashes[HashAlgorithmOV.MD5] == "5eb63bbbe01eeed093cb22bb8f5acdc3"
    )
    assert (  # noqa: S101
        reference.hashes[HashAlgorithmOV.SHA1]
        == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    )
