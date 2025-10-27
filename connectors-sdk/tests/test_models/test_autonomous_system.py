import pytest
import stix2
from connectors_sdk.models import (
    AssociatedFile,
    ExternalReference,
    OrganizationAuthor,
    TLPMarking,
)
from connectors_sdk.models.autonomous_system import AutonomousSystem
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from pydantic import ValidationError


def test_autonomous_system_is_a_base_identified_entity():
    """Test that AutonomousSystem is a BaseIdentifiedEntity."""
    # Given the AutonomousSystem class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(AutonomousSystem, BaseIdentifiedEntity)


def test_autonomous_system_class_should_not_accept_invalid_input():
    """Test that AutonomousSystem class should not accept invalid input."""
    # Given: An invalid input data for AutonomousSystem
    input_data = {
        "name": "Test autonomous_system",
        "invalid_key": "invalid_value",
    }
    # When validating the autonomous_system
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        AutonomousSystem.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_autonomous_system_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that AutonomousSystem to_stix2_object method returns a valid STIX2.1 AutonomousSystem."""
    # Given: A valid AutonomousSystem instance
    autonomous_system = AutonomousSystem(
        # BaseIdentifiedEntity properties
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
        # AS minimum properties
        number=64512,
    )
    # When: calling to_stix2_object method
    stix2_obj = autonomous_system.to_stix2_object()
    # Then: A valid STIX2.1 Location is returned
    assert isinstance(stix2_obj, stix2.AutonomousSystem)


def test_autonomous_system_to_stix2_object(
    fake_valid_organization_author: OrganizationAuthor,
    fake_valid_tlp_markings: list[TLPMarking],
    fake_valid_external_references: list[ExternalReference],
) -> None:
    """Test that AutonomousSystem to_stix2_object method returns correct STIX2.1 Location."""
    # Given: A valid AutonomousSystem instance
    autonomous_system = AutonomousSystem(
        # BaseIdentifiedEntity properties
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
        # Observable properties
        score=85,
        description="Test description",
        labels=["test", "autonomous_system"],
        associated_files=[
            AssociatedFile(
                name="test_file.pem",
                content=b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
                mime_type="application/x-pem-file",
            )
        ],
        create_indicator=True,
        # AutonomousSystem properties
        number=64512,
        name="Test AS",
        rir="ARIN",
    ).to_stix2_object()

    assert autonomous_system == stix2.AutonomousSystem(
        allow_custom=True,
        # BaseIdentifiedEntity properties
        object_marking_refs=[
            marking.to_stix2_object().id for marking in fake_valid_tlp_markings
        ],
        x_opencti_external_references=[
            external_ref.to_stix2_object()
            for external_ref in fake_valid_external_references
        ],
        x_opencti_created_by_ref=fake_valid_organization_author.to_stix2_object().id,
        # Observable properties
        x_opencti_score=85,
        x_opencti_description="Test description",
        x_opencti_labels=["test", "autonomous_system"],
        x_opencti_files=[
            file.to_stix2_object()
            for file in [
                AssociatedFile(
                    name="test_file.pem",
                    content=b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
                    mime_type="application/x-pem-file",
                )
            ]
        ],
        x_opencti_create_indicator=True,
        # AutonomousSystem properties
        number=64512,
        name="Test AS",
        rir="ARIN",
    )
