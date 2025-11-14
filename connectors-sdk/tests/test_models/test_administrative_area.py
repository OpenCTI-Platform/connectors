import pycti
import pytest
from connectors_sdk.models import ExternalReference, OrganizationAuthor, TLPMarking
from connectors_sdk.models.administrative_area import AdministrativeArea
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from pydantic import ValidationError
from stix2.v21 import Location as Stix2Location


def test_administrative_area_is_a_base_identified_entity():
    """Test that AdministrativeArea is a BaseIdentifiedEntity."""
    # Given the AdministrativeArea class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(AdministrativeArea, BaseIdentifiedEntity)


def test_administrative_area_class_should_not_accept_invalid_input():
    """Test that AdministrativeArea class should not accept invalid input."""
    # Given: An invalid input data for AdministrativeArea
    input_data = {
        "name": "Test administrative_area",
        "invalid_key": "invalid_value",
    }
    # When validating the administrative_area
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        AdministrativeArea.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_administrative_area_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that AdministrativeArea to_stix2_object method returns a valid STIX2.1 AdministrativeArea."""
    # Given: A valid AdministrativeArea instance
    administrative_area = AdministrativeArea(
        name="Test administrative_area",
        description="Test description",
        latitude=48.866667,
        longitude=2.333333,
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = administrative_area.to_stix2_object()
    # Then: A valid STIX2.1 Location is returned
    assert isinstance(stix2_obj, Stix2Location)


def test_administrative_area_to_stix2_object(
    fake_valid_organization_author: OrganizationAuthor,
    fake_valid_tlp_markings: list[TLPMarking],
    fake_valid_external_references: list[ExternalReference],
) -> None:
    """Test that AdministrativeArea to_stix2_object method returns correct STIX2.1 Location."""
    administrative_area = AdministrativeArea(
        name="Bouche du Rhone",
        latitude=48.8566,
        longitude=2.3522,
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    ).to_stix2_object()

    assert administrative_area == Stix2Location(
        id=pycti.Location.generate_id(
            name="Bouche du Rhone",
            x_opencti_location_type="Administrative-Area",
            latitude=48.8566,
            longitude=2.3522,
        ),
        name="Bouche du Rhone",
        administrative_area="Bouche du Rhone",
        latitude=48.8566,
        longitude=2.3522,
        created_by_ref=fake_valid_organization_author.to_stix2_object().id,
        object_marking_refs=[
            marking.to_stix2_object().id for marking in fake_valid_tlp_markings
        ],
        external_references=[
            external_ref.to_stix2_object()
            for external_ref in fake_valid_external_references
        ],
        created=administrative_area.created,
        modified=administrative_area.modified,
        custom_properties=dict(
            x_opencti_location_type="Administrative-Area",
        ),
    )
