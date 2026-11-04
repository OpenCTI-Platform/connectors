import pytest
import stix2
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import Reliability
from connectors_sdk.models.organization import Organization
from pycti import STIX_EXT_OCTI
from pydantic import ValidationError
from stix2.v21 import Identity as Stix2Identity

### ORGANIZATION


def test_organization_is_a_base_identified_entity():
    """Test that Organization is a BaseIdentifiedEntity."""
    # Given the Organization class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Organization, BaseIdentifiedEntity)


def test_organization_class_should_not_accept_invalid_input():
    """Test that Organization class should not accept invalid input."""
    # Given: An invalid input data for Organization
    input_data = {
        "name": "Test organization",
        "invalid_key": "invalid_value",
    }
    # When validating the organization
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Organization.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_organization_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Organization to_stix2_object method returns a valid STIX2.1 Organization."""
    # Given: A valid Organization instance
    organization = Organization(
        name="Test organization",
        description="Test description",
        contact_information="contact@test.com",
        organization_type="vendor",
        reliability=Reliability.A,
        aliases=["Test alias"],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = organization.to_stix2_object()
    # Then: A valid STIX2.1 Identity is returned
    assert isinstance(stix2_obj, Stix2Identity)


def test_organization_writes_opencti_properties_in_extension():
    """Test that Organization writes its OpenCTI properties in the OpenCTI extension."""
    # Given an Organization with OpenCTI properties
    organization = Organization(
        name="Test organization",
        organization_type="vendor",
        reliability=Reliability.A,
        aliases=["Test alias"],
    )
    # When converting it to a STIX object
    stix2_obj = organization.to_stix2_object()
    # Then the extension holds the properties
    assert stix2_obj.extensions[STIX_EXT_OCTI] == {
        "extension_type": "property-extension",
        "organization_type": "vendor",
        "reliability": Reliability.A,
        "aliases": ["Test alias"],
    }
    # And the deprecated x_opencti_* properties are still there
    assert stix2_obj.x_opencti_reliability == Reliability.A
    # And the serialized object is still valid STIX with the same id
    parsed = stix2.parse(stix2_obj.serialize(), allow_custom=True)
    assert parsed.id == Organization(name="Test organization").to_stix2_object().id
