# pragma: no cover  # do not compute coverage on test files
"""Offer tests for observations OpenCTI entities."""

import pytest
import stix2
from connectors_sdk.models.octi._common import BaseIdentifiedEntity
from connectors_sdk.models.octi.knowledge.entities import Organization, Sector
from pydantic import ValidationError

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
        reliability="A - Completely reliable",
        aliases=["Test alias"],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = organization.to_stix2_object()
    # Then: A valid STIX2.1 Identity is returned
    assert isinstance(stix2_obj, stix2.v21.Identity)


#### SECTOR


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
        reliability="A - Completely reliable",
        aliases=["Test alias"],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )

    # When: calling to_stix2_object method
    stix2_obj = sector.to_stix2_object()

    # Then: A valid STIX Identity is returned
    assert isinstance(stix2_obj, stix2.Identity)
