import pycti
import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.country import Country
from pydantic import ValidationError
from stix2.v21 import Location as Stix2Location


def test_country_is_a_base_identified_entity():
    """Test that Country is a BaseIdentifiedEntity."""
    # Given the Country class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Country, BaseIdentifiedEntity)


def test_country_class_should_not_accept_invalid_input():
    """Test that Country class should not accept invalid input."""
    # Given: An invalid input data for Country
    input_data = {
        "name": "Test country",
        "invalid_key": "invalid_value",
    }
    # When validating the country
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Country.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_country_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Country to_stix2_object method returns a valid STIX2.1 Country."""
    # Given: A valid Country instance
    country = Country(
        name="Test country",
        description="Test description",
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = country.to_stix2_object()
    # Then: A valid STIX2.1 Location is returned
    assert isinstance(stix2_obj, Stix2Location)


def test_country_to_stix2_object(
    fake_valid_organization_author,
    fake_valid_tlp_markings,
    fake_valid_external_references,
) -> None:
    """Test that Country to_stix2_object method returns correct STIX2.1 Location."""
    country = Country(
        name="France",
        description="Country in Western Europe",
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    ).to_stix2_object()

    assert country == Stix2Location(
        id=pycti.Location.generate_id(
            name="France",
            x_opencti_location_type="Country",
        ),
        name="France",
        country="France",
        description="Country in Western Europe",
        allow_custom=True,
        created_by_ref=fake_valid_organization_author.id,
        object_marking_refs=[marking.id for marking in fake_valid_tlp_markings],
        external_references=[
            ext_ref.to_stix2_object() for ext_ref in fake_valid_external_references
        ],
        created=country.created,
        modified=country.modified,
        custom_properties=dict(
            x_opencti_location_type="Country",
        ),
    )
