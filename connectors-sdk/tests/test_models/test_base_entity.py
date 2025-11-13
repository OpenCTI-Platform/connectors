"""Offer tests for common OpenCTI entities."""

from typing import OrderedDict

import pytest
import stix2
import stix2.properties
from connectors_sdk.models.base_object import BaseObject
from pydantic import Field, ValidationError


def test_base_entity_should_not_implement_to_stix2_object_method():
    """Test that BaseObject does not implement to_stix2_object method."""
    # Given Base Entity definition
    # When trying to instantiate BaseObject
    # Then it should raise an TypeError indicating that to_stix2_object is not implemented
    with pytest.raises(TypeError) as error:
        BaseObject().to_stix2_object()
        assert "to_stix2_object" in str(error)


@pytest.fixture
def implemented_base_entity():
    """Fixture to provide an implemented BaseObject."""

    class ImplementedBaseEntity(BaseObject):
        """A concrete implementation of BaseObject for testing."""

        toto: str
        titi: int | None = Field(None, ge=0, le=100)

        def to_stix2_object(self) -> stix2.v21._STIXBase21:
            class DummyStixObject(stix2.v21._STIXBase21):
                _properties = OrderedDict(
                    [
                        ("spec_version", stix2.properties.StringProperty(fixed="2.1")),
                        ("name", stix2.properties.StringProperty()),
                    ]
                )

            return DummyStixObject(name=f"{self.toto}{self.titi}")

    return ImplementedBaseEntity


@pytest.mark.parametrize(
    "set_properties, unset_properties",
    [
        pytest.param({"toto": "toto", "titi": 1}, [], id="all properties set"),
        pytest.param({"toto": "toto"}, ["titi"], id="some properties unset"),
    ],
)
def test_base_entity_should_have_properties_set_and_properties_unset_attributes(
    implemented_base_entity, set_properties, unset_properties
):
    """Test that BaseObject has the correct properties set and unset."""
    # Given an implemented BaseObject
    entity_class = implemented_base_entity
    # When creating an instance of the entity with specific properties
    entity_instance = entity_class(**set_properties)
    # Then the instance should have the proper properties_set and properties_unset attributes
    assert entity_instance.properties_set == set(set_properties.keys())
    assert entity_instance.properties_unset == set(unset_properties)


def test_base_entity_should_update_properties_set_and_properties_unset(
    implemented_base_entity,
):
    """Test that BaseObject update set properties."""
    # Given an implemented BaseObject
    entity_class = implemented_base_entity
    # When creating an instance of the entity
    entity_instance = entity_class(toto="toto")
    # and modifying a property
    entity_instance.titi = 0

    # Then the properties_set and properties_unset should be updated correct
    assert entity_instance.properties_set == {"toto", "titi"}
    assert entity_instance.properties_unset == set()


@pytest.mark.parametrize(
    "properties",
    [
        # invalid type
        pytest.param({"toto": 123, "titi": "string"}, id="invalid types"),
        # invalid value
        pytest.param({"toto": "toto", "titi": -1}, id="invalid value"),
        # missing required property
        pytest.param({"titi": 1}, id="missing required property"),
        # extra property not defined in the model
        pytest.param(
            {"toto": "toto", "titi": 1, "extra_property": "extra"}, id="extra property"
        ),
    ],
)
def test_base_entity_should_not_allow_invalid_property(
    implemented_base_entity, properties
):
    """Test that BaseObject does not allow invalid properties."""
    # Given an implemented BaseObject
    entity_class = implemented_base_entity
    # When trying to set an invalid property
    with pytest.raises(ValidationError):
        entity_class(**properties)


def test_base_entity_should_revalidate_model_when_an_attribute_is_set(
    implemented_base_entity,
):
    """Test that BaseObject revalidates the model when an attribute is set."""
    # Given an implemented BaseObject
    entity_class = implemented_base_entity
    # When creating an instance of the entity
    entity_instance = entity_class(toto="toto", titi=1)
    # and later setting an invalid value
    # Then it should raise a ValidationError
    with pytest.raises(ValidationError) as error:
        entity_instance.titi = -1
        assert "titi" in str(error.value)


def test_base_entity_can_be_hashed(implemented_base_entity):
    """Test that BaseObject can be hashed."""
    # Given an implemented BaseObject
    entity_class = implemented_base_entity
    # When creating an instance of the entity
    entity_instance = entity_class(toto="toto", titi=1)
    # Then it should be hashable
    assert isinstance(hash(entity_instance), int)


def test_base_entity_can_be_compared(implemented_base_entity):
    """Test that BaseObject can be compared."""
    # Given two instances of the implemented BaseObject
    entity_class = implemented_base_entity
    entity_instance1 = entity_class(toto="toto", titi=1)
    entity_instance2 = entity_class(toto="toto", titi=1)
    # When comparing them
    # Then they should be equal
    assert entity_instance1 == entity_instance2


def test_base_entity_cannot_be_compared_with_different_class(implemented_base_entity):
    """Test that BaseObject cannot be compared with a different class."""
    # Given an instance of the implemented BaseObject
    entity_class = implemented_base_entity
    entity_instance = entity_class(toto="toto", titi=1)

    # When comparing it with an instance of a different class
    class DifferentClass:
        pass

    different_instance = DifferentClass()
    # Then it should raise a TypeError
    with pytest.raises(NotImplementedError):
        _ = entity_instance == different_instance
