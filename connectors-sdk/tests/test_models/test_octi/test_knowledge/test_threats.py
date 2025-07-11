# pragma: no cover  # do not compute coverage on test files
"""Offer tests for observations OpenCTI entities."""

import pytest
import stix2
from connectors_sdk.models.octi._common import BaseIdentifiedEntity
from connectors_sdk.models.octi.knowledge.threats import IntrusionSet
from pydantic import ValidationError

### INTRUSION SET


def test_intrusion_set_is_a_base_identified_entity():
    """Test that IntrusionSet is a BaseIdentifiedEntity."""
    # Given the IntrusionSet class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(IntrusionSet, BaseIdentifiedEntity)


def test_intrusion_set_class_should_not_accept_invalid_input():
    """Test that IntrusionSet class should not accept invalid input."""
    # Given: An invalid input data for IntrusionSet
    input_data = {
        "name": "Test intrusion set",
        "invalid_key": "invalid_value",
    }
    # When validating the intrusion set
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        IntrusionSet.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_intrusion_set_should_not_accept_incoherent_dates():
    """Test that IntrusionSet should not accept incoherent dates."""
    # Given an invalid input data for IntrusionSet with first_seen after last_seen
    input_data = {
        "name": "Test IntrusionSet",
        "first_seen": "2024-01-01T00:00:00+00:00",
        "last_seen": "2023-01-01T00:00:00+00:00",
    }
    # When validating the intrusion set
    # Then It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        _ = IntrusionSet.model_validate(input_data)
        assert all(
            w in str(error.value.errors()[0]) for w in ("'last_seen'", "'first_seen'")
        )


def test_intrusion_set_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that IntrusionSet to_stix2_object method returns a valid STIX2.1 IntrusionSet."""
    # Given: A valid IntrusionSet instance
    intrusion_set = IntrusionSet(
        name="Test intrusion set",
        description="Test description",
        first_seen="2023-01-01T00:00:00Z",
        last_seen="2024-01-01T00:00:00Z",
        aliases=["Test alias"],
        goals=["Test goal"],
        resource_level="individual",
        primary_motivation="personal-gain",
        secondary_motivations=["personal-satisfaction"],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = intrusion_set.to_stix2_object()
    # Then: A valid STIX2.1 IntrusionSet is returned
    assert isinstance(stix2_obj, stix2.v21.IntrusionSet)
