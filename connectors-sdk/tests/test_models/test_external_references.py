import pytest
import stix2
import stix2.properties
from connectors_sdk.models.base_object import BaseObject
from connectors_sdk.models.external_reference import ExternalReference


def test_external_reference_should_be_a_base_entity():
    """Test that ExternalReference is a BaseObject."""
    # Given the ExternalReference class
    # When checking the class inheritance
    # Then it should be a subclass of BaseObject
    assert issubclass(ExternalReference, BaseObject)


@pytest.mark.parametrize(
    "properties",
    [
        pytest.param({"source_name": "example_source"}, id="minimal valid properties"),
        pytest.param(
            {
                "source_name": "example_source",
                "description": "A sample external reference",
                "url": "https://example.com",
                "external_id": "ext-123",
            },
            id="all valid properties",
        ),
    ],
)
def test_external_reference_should_allow_valid_properties(properties):
    """Test that ExternalReference allows valid properties."""
    # Given the ExternalReference class
    # When creating an instance with valid properties
    external_reference = ExternalReference(**properties)
    # Then it should have the properties set correctly
    for key, value in properties.items():
        assert getattr(external_reference, key) == value


def test_external_reference_should_convert_to_stix2_object():
    """Test that ExternalReference can convert to a STIX-like object."""
    # Given an ExternalReference instance
    external_reference = ExternalReference(
        source_name="example_source",
        url="https://example.com",
    )
    # When converting to a STIX-like object
    stix_object = external_reference.to_stix2_object()
    # Then the STIX-like object should have the correct properties
    assert isinstance(stix_object, stix2.v21.ExternalReference)
