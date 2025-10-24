import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.city import City
from pydantic import ValidationError
from stix2.v21 import Location as Stix2Location


def test_city_is_a_base_identified_entity():
    """Test that City is a BaseIdentifiedEntity."""
    # Given the City class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(City, BaseIdentifiedEntity)


def test_city_class_should_not_accept_invalid_input():
    """Test that City class should not accept invalid input."""
    # Given: An invalid input data for City
    input_data = {
        "name": "Test city",
        "invalid_key": "invalid_value",
    }
    # When validating the city
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        City.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_city_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that City to_stix2_object method returns a valid STIX2.1 City."""
    # Given: A valid City instance
    city = City(
        name="Test city",
        description="Test description",
        latitude=48.866667,
        longitude=2.333333,
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = city.to_stix2_object()
    # Then: A valid STIX2.1 Location is returned
    assert isinstance(stix2_obj, Stix2Location)
