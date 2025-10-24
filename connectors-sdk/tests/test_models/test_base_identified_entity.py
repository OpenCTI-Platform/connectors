from typing import OrderedDict

import pytest
import stix2
import stix2.properties
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.base_object import BaseObject
from pydantic import Field, ValidationError


@pytest.fixture
def implemented_base_identified_entity():
    """Fixture to provide an implemented BaseIdentifiedEntity."""

    class ImplementedBaseIdentifiedEntity(BaseIdentifiedEntity):
        """A concrete implementation of BaseIdentifiedEntity for testing."""

        toto: str
        titi: int | None = Field(None, ge=0, le=100)

        def to_stix2_object(self) -> stix2.v21._STIXBase21:
            class DummyStixObject(stix2.v21._STIXBase21):
                _properties = OrderedDict(
                    [
                        ("spec_version", stix2.properties.StringProperty(fixed="2.1")),
                        ("name", stix2.properties.StringProperty()),
                        (
                            "id",
                            stix2.properties.IDProperty(
                                type="base-identified-entity", spec_version="2.1"
                            ),
                        ),
                    ]
                )

            # _id = f"base-identified-entity--123e4567-e89b-12d3-a456-42665544{"".join(str(ord(c)) for c in str(self.titi))[:4].ljust(4, '0')}"
            # Not supported in python 3.11 => splitted to avoid generator in f-string
            encoded = "".join(str(ord(c)) for c in str(self.titi))[:4].ljust(4, "0")
            _id = f"base-identified-entity--123e4567-e89b-12d3-a456-42665544{encoded}"
            return DummyStixObject(
                id=_id,
                name=f"{self.toto}{self.titi}",
            )

    return ImplementedBaseIdentifiedEntity


def test_base_identified_entity_should_be_a_base_entity(
    implemented_base_identified_entity,
):
    """Test that BaseIdentifiedEntity is a BaseObject."""
    # Given an implemented BaseIdentifiedEntity
    entity_class = implemented_base_identified_entity
    # When checking the class inheritance
    # Then it should be a subclass of BaseObject
    assert issubclass(entity_class, BaseObject)


def test_base_identified_entity_should_have_id(implemented_base_identified_entity):
    """Test that BaseIdentifiedEntity has an id."""
    # Given an implemented BaseIdentifiedEntity
    entity_class = implemented_base_identified_entity
    # When creating an instance of the entity
    entity_instance = entity_class(toto="toto", titi=1)
    # Then the instance should have an id
    assert hasattr(entity_instance, "id")
    assert isinstance(entity_instance.id, str)
    assert entity_instance.id.startswith("base-identified-entity--")


def test_base_identified_entity_should_raise_error_if_stix_representation_does_not_have_id(
    implemented_base_identified_entity,
):
    """Test that BaseIdentifiedEntity raises an error if the STIX representation does not have an id."""

    # Given an implemented BaseIdentifiedEntity whose STIX representation does not have an id
    class InvalidBaseIdentifiedEntity(implemented_base_identified_entity):
        """An invalid implementation of BaseIdentifiedEntity for testing."""

        def to_stix2_object(self) -> stix2.v21._STIXBase21:
            class DummyStixObject(stix2.v21._STIXBase21):
                _properties = OrderedDict(
                    [
                        ("spec_version", stix2.properties.StringProperty(fixed="2.1")),
                        ("name", stix2.properties.StringProperty()),
                    ]
                )

            return DummyStixObject(name=f"{self.toto}{self.titi}")

    # When trying to create an instance of the invalid entity
    with pytest.raises(ValidationError) as error:
        InvalidBaseIdentifiedEntity(toto="toto", titi=1)
        assert "'id' property must be set" in str(error.value)


def test_base_identified_entity_id_shouldbe_read_only(
    implemented_base_identified_entity,
):
    """Test that BaseIdentifiedEntity id is read-only."""
    # Given an implemented BaseIdentifiedEntity
    entity_class = implemented_base_identified_entity
    # When creating an instance of the entity
    entity_instance = entity_class(toto="toto", titi=1)
    # Then the id should be read-only
    with pytest.raises(AttributeError) as error:
        entity_instance.id = "new-id"
        assert "'id'" in str(error.value)


@pytest.mark.parametrize(
    "common_param_name",
    [
        pytest.param("external_references", id="external_references"),
        pytest.param("author", id="author"),
        pytest.param("markings", id="markings"),
    ],
)
def test_base_identified_entity_should_have_common_params(
    implemented_base_identified_entity, common_param_name
):
    """Test that BaseIdentifiedEntity has common parameters."""
    # Given an implemented BaseIdentifiedEntity
    entity_class = implemented_base_identified_entity
    # When creating an instance of the entity
    entity_instance = entity_class(toto="toto", titi=1)
    # Then the instance should have the common parameter
    assert hasattr(entity_instance, common_param_name)


def test_base_identified_entity_should_emit_warning_if_id_is_changed(
    implemented_base_identified_entity,
):
    """Test that BaseIdentifiedEntity emits a warning if the id is changed."""
    # Given an instance of a BaseIdentifiedEntity whose id depends on titi vaue
    entity_class = implemented_base_identified_entity
    entity_instance = entity_class(toto="toto")
    # When changing the id by setting value to titi
    # Then it should emit a warning
    with pytest.warns(UserWarning) as warning:
        entity_instance.titi = 1
        assert "'id' property" in str(warning[0].message)
