"""Offer tests for common OpenCTI entities."""

import pytest
import stix2
import stix2.properties
from connectors_sdk.models.base_object import BaseObject
from connectors_sdk.models.tlp_marking import TLPMarking
from pydantic import ValidationError


def test_tlp_marking_should_be_a_base_entity():
    """Test that TLPMarking is a BaseObject."""
    # Given the TLPMarking class
    # When checking the class inheritance
    # Then it should be a subclass of BaseObject
    assert issubclass(TLPMarking, BaseObject)


@pytest.mark.parametrize(
    "level",
    [
        pytest.param("red", id="red level"),
        pytest.param("amber+strict", id="amber+strict OCTI custom level"),
        pytest.param("amber", id="amber level"),
        pytest.param("green", id="green level"),
        pytest.param("white", id="white level"),
    ],
)
def test_tlp_marking_should_allow_valid_levels(level):
    """Test that TLPMarking allows valid levels."""
    # Given the TLPMarking class
    # When creating an instance with a valid level
    tlp_marking = TLPMarking(level=level)
    # Then it should have the level set correctly
    assert tlp_marking.level == level


def test_tlp_marking_should_not_allow_invalid_levels():
    """Test that TLPMarking does not allow invalid levels."""
    # Given the TLPMarking class
    # When trying to create an instance with an invalid level
    with pytest.raises(ValidationError) as error:
        TLPMarking(level="invalid")
        assert "value is not a valid enumeration member" in str(error.value)


def test_tlp_marking_should_convert_to_stix2_object():
    """Test that TLPMarking can convert to a STIX-like object."""
    # Given a TLPMarking instance
    tlp_marking = TLPMarking(level="red")
    # When converting to a STIX-like object
    stix_object = tlp_marking.to_stix2_object()
    # Then the STIX-like object should have the correct properties
    assert isinstance(stix_object, stix2.v21.MarkingDefinition)
