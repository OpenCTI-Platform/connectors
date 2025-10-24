import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import Reliability
from connectors_sdk.models.sector import Sector
from pydantic import ValidationError
from stix2.v21 import Identity as Stix2Identity


def test_sector_is_a_base_identified_entity():
    """Test that Sector is a BaseIdentifiedEntity."""
    # Given the Sector class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Sector, BaseIdentifiedEntity)


def test_sector_should_not_accept_invalid_input():
    """Test that Sector should not accept incoherent dates."""
    # Given an invalid input data for Sector
    input_data = {
        "name": "Test Sector",
        "invalid_key": "invalid_value",
    }
    # When validating the sector
    # Then It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        _ = Sector.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_sector_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Sector.to_stix2_object returns a valid STIX Sector."""
    # Given: A valid sector input data
    sector = Sector(
        name="Test sector",
        description="Test description",
        sectors=["Test sector"],
        reliability=Reliability.A,
        aliases=["Test alias"],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )

    # When: calling to_stix2_object method
    stix2_obj = sector.to_stix2_object()

    # Then: A valid STIX Identity is returned
    assert isinstance(stix2_obj, Stix2Identity)
