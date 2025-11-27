import pycti
import pytest
from connectors_sdk.models import ExternalReference, OrganizationAuthor, TLPMarking
from connectors_sdk.models._location import Location as Stix2Location
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.region import Region
from pydantic import ValidationError


def test_region_is_a_base_identified_entity() -> None:
    """Test that Region is a BaseIdentifiedEntity."""
    # Given the Region class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Region, BaseIdentifiedEntity)


def test_region_class_should_not_accept_invalid_input() -> None:
    """Test that Region class should not accept invalid input."""
    # Given: An invalid input data for Region
    input_data = {
        "name": "Test region",
        "invalid_key": "invalid_value",
    }
    # When validating the region
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Region.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_region_to_stix2_object(
    fake_valid_organization_author: OrganizationAuthor,
    fake_valid_tlp_markings: list[TLPMarking],
    fake_valid_external_references: list[ExternalReference],
) -> None:
    """Test that Region to_stix2_object method returns correct STIX2.1 Location."""
    region = Region(
        name="Europe",
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    ).to_stix2_object()

    assert region == Stix2Location(
        id=pycti.Location.generate_id(
            name="Europe",
            x_opencti_location_type="Region",
        ),
        name="Europe",
        region="Europe",
        created_by_ref=fake_valid_organization_author.to_stix2_object().id,
        object_marking_refs=[
            marking.to_stix2_object().id for marking in fake_valid_tlp_markings
        ],
        external_references=[
            external_ref.to_stix2_object()
            for external_ref in fake_valid_external_references
        ],
        created=region.created,
        modified=region.modified,
        custom_properties=dict(
            x_opencti_location_type="Region",
        ),
    )
