import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import Reliability
from connectors_sdk.models.system import System
from pydantic import ValidationError
from stix2.v21 import Identity as Stix2Identity


def test_system_is_a_base_identified_entity():
    """Test that System is a BaseIdentifiedEntity."""
    # Given the System class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(System, BaseIdentifiedEntity)


def test_system_class_should_not_accept_invalid_input():
    """Test that System class should not accept invalid input."""
    # Given: An invalid input data for System
    input_data = {
        "name": "Test system",
        "invalid_key": "invalid_value",
    }
    # When validating the system
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        System.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_system_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that System to_stix2_object method returns a valid STIX2.1 Identity."""
    # Given: A valid System instance
    system = System(
        name="WordPress",
        description="Test description",
        contact_information="contact@test.com",
        reliability=Reliability.A,
        aliases=["Test alias"],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = system.to_stix2_object()
    # Then: A valid STIX2.1 Identity is returned
    assert isinstance(stix2_obj, Stix2Identity)


def test_system_to_stix2_object_has_system_identity_class():
    """Test that System to_stix2_object method sets identity_class to 'system'."""
    # Given: A valid System instance
    system = System(name="WordPress")
    # When: calling to_stix2_object method
    stix2_obj = system.to_stix2_object()
    # Then: The identity_class is 'system'
    assert stix2_obj.identity_class == "system"
