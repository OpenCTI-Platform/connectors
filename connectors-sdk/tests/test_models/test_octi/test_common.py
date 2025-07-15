"""Offer tests for common OpenCTI entities."""

from typing import OrderedDict

import pytest
import stix2
import stix2.properties
from connectors_sdk.models.octi._common import (
    AssociatedFile,
    AssociatedFileStix,
    Author,
    BaseEntity,
    BaseIdentifiedEntity,
    ExternalReference,
    TLPMarking,
    _ModelRegistry,
)
from pydantic import Field, ValidationError

### TEST BASEENTITY


def test_base_entity_should_not_implement_to_stix2_object_method():
    """Test that BaseEntity does not implement to_stix2_object method."""
    # Given Base Entity definition
    # When trying to instantiate BaseEntity
    # Then it should raise an TypeError indicating that to_stix2_object is not implemented
    with pytest.raises(TypeError) as error:
        BaseEntity().to_stix2_object()
        assert "to_stix2_object" in str(error)


@pytest.fixture
def implemented_base_entity():
    """Fixture to provide an implemented BaseEntity."""

    class ImplementedBaseEntity(BaseEntity):
        """A concrete implementation of BaseEntity for testing."""

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
    """Test that BaseEntity has the correct properties set and unset."""
    # Given an implemented BaseEntity
    entity_class = implemented_base_entity
    # When creating an instance of the entity with specific properties
    entity_instance = entity_class(**set_properties)
    # Then the instance should have the proper properties_set and properties_unset attributes
    assert entity_instance.properties_set == set(set_properties.keys())
    assert entity_instance.properties_unset == set(unset_properties)


def test_base_entity_should_update_properties_set_and_properties_unset(
    implemented_base_entity,
):
    """Test that BaseEntity update set properties."""
    # Given an implemented BaseEntity
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
    """Test that BaseEntity does not allow invalid properties."""
    # Given an implemented BaseEntity
    entity_class = implemented_base_entity
    # When trying to set an invalid property
    with pytest.raises(ValidationError):
        entity_class(**properties)


def test_base_entity_should_revalidate_model_when_an_attribute_is_set(
    implemented_base_entity,
):
    """Test that BaseEntity revalidates the model when an attribute is set."""
    # Given an implemented BaseEntity
    entity_class = implemented_base_entity
    # When creating an instance of the entity
    entity_instance = entity_class(toto="toto", titi=1)
    # and later setting an invalid value
    # Then it should raise a ValidationError
    with pytest.raises(ValidationError) as error:
        entity_instance.titi = -1
        assert "titi" in str(error.value)


def test_base_entity_can_be_hashed(implemented_base_entity):
    """Test that BaseEntity can be hashed."""
    # Given an implemented BaseEntity
    entity_class = implemented_base_entity
    # When creating an instance of the entity
    entity_instance = entity_class(toto="toto", titi=1)
    # Then it should be hashable
    assert isinstance(hash(entity_instance), int)


def test_base_entity_can_be_compared(implemented_base_entity):
    """Test that BaseEntity can be compared."""
    # Given two instances of the implemented BaseEntity
    entity_class = implemented_base_entity
    entity_instance1 = entity_class(toto="toto", titi=1)
    entity_instance2 = entity_class(toto="toto", titi=1)
    # When comparing them
    # Then they should be equal
    assert entity_instance1 == entity_instance2


def test_base_entity_cannot_be_compared_with_different_class(implemented_base_entity):
    """Test that BaseEntity cannot be compared with a different class."""
    # Given an instance of the implemented BaseEntity
    entity_class = implemented_base_entity
    entity_instance = entity_class(toto="toto", titi=1)

    # When comparing it with an instance of a different class
    class DifferentClass:
        pass

    different_instance = DifferentClass()
    # Then it should raise a TypeError
    with pytest.raises(NotImplementedError):
        _ = entity_instance == different_instance


### TEST BASEIDENTIFIEDENTITY


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
    """Test that BaseIdentifiedEntity is a BaseEntity."""
    # Given an implemented BaseIdentifiedEntity
    entity_class = implemented_base_identified_entity
    # When checking the class inheritance
    # Then it should be a subclass of BaseEntity
    assert issubclass(entity_class, BaseEntity)


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


### TEST AUTHOR


@pytest.fixture
def implemented_author():
    """Fixture to provide an implemented Author."""

    class ImplementedAuthor(Author):
        """A concrete implementation of Author for testing."""

        name: str
        email: str | None = Field(None, description="Email of the author.")

        def to_stix2_object(self) -> stix2.v21._STIXBase21:
            class DummyStixObject(stix2.v21._STIXBase21):
                _properties = OrderedDict(
                    [
                        ("spec_version", stix2.properties.StringProperty(fixed="2.1")),
                        ("name", stix2.properties.StringProperty()),
                        (
                            "id",
                            stix2.properties.IDProperty(
                                type="author", spec_version="2.1"
                            ),
                        ),
                    ]
                )

            return DummyStixObject(id=f"author--{self.name}", name=self.name)

    return ImplementedAuthor


def test_author_should_be_a_base_identified_entity(implemented_author):
    """Test that Author is a BaseIdentifiedEntity."""
    # Given an implemented Author
    author_class = implemented_author
    # When checking the class inheritance
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(author_class, BaseIdentifiedEntity)


### TEST ASSOCIATEDFILE


def test_associated_file_stix_is_stix2_object():
    """Test that AssociatedFileStix is a valid STIX object."""
    # Given the AssociatedFileStix class
    # When checking the class inheritance
    # Then it should be a subclass of stix2.v21._STIXBase21
    assert issubclass(AssociatedFileStix, stix2.v21._STIXBase21)


def test_associated_file_stix_should_have_required_properties():
    """Test that AssociatedFileStix has required properties."""
    # Given the AssociatedFileStix class and correct paarameters
    # When instantiating it
    associated_file_stix = AssociatedFileStix(
        name="example_file.txt",
        data="VGhpcyBpcyBhbiBleGFtcGxlIGZpbGUgY29udGVudC4=",  # Base64 encoded content
        mime_type="text/plain",
    )
    # Then it should have the required properties set correctly
    assert associated_file_stix["name"] == "example_file.txt"
    assert (
        associated_file_stix["data"] == "VGhpcyBpcyBhbiBleGFtcGxlIGZpbGUgY29udGVudC4="
    )
    assert associated_file_stix["mime_type"] == "text/plain"


def test_associated_file_should_be_a_base_entity():
    """Test that AssociatedFile is a BaseEntity."""
    # Given the AssociatedFile class
    # When checking the class inheritance
    # Then it should be a subclass of BaseEntity
    assert issubclass(AssociatedFile, BaseEntity)


@pytest.mark.parametrize(
    "properties",
    [
        pytest.param({"name": "example_file.txt"}, id="minimal valid properties"),
        pytest.param(
            {
                "name": "example_file.txt",
                "description": "A sample file",
                "content": b"Sample content",
                "mime_type": "text/plain",
                "markings": [TLPMarking(level="red")],
                "version": "1.0",
            },
            id="all valid propertiesn",
        ),
    ],
)
def test_associated_file_should_allow_valid_properties(properties):
    """Test that AssociatedFile allows valid properties."""
    # Given the AssociatedFile class
    # When creating an instance with valid properties
    associated_file = AssociatedFile(**properties)
    # Then it should have the properties set correctly
    for key, value in properties.items():
        assert getattr(associated_file, key) == value


def test_associated_file_should_convert_to_stix2_object():
    """Test that AssociatedFile can convert to a STIX-like object."""
    # Given an AssociatedFile instance
    associated_file = AssociatedFile(
        name="example_file.txt",
    )
    # When converting to a STIX-like object
    stix_object = associated_file.to_stix2_object()
    # Then the STIX-like object should have the correct properties
    assert isinstance(stix_object, AssociatedFileStix)
    assert stix_object["name"] == "example_file.txt"


### TEST EXTERNALREFERENCE


def test_external_reference_should_be_a_base_entity():
    """Test that ExternalReference is a BaseEntity."""
    # Given the ExternalReference class
    # When checking the class inheritance
    # Then it should be a subclass of BaseEntity
    assert issubclass(ExternalReference, BaseEntity)


@pytest.mark.parametrize(
    "properties",
    [
        pytest.param({"source_name": "example_source"}, id="minimal valid properties"),
        pytest.param(
            {
                "source_name": "example_source",
                "description": "A sample external reference",
                "url": "https://example.com",
                "external_id": "ext-123",
            },
            id="all valid properties",
        ),
    ],
)
def test_external_reference_should_allow_valid_properties(properties):
    """Test that ExternalReference allows valid properties."""
    # Given the ExternalReference class
    # When creating an instance with valid properties
    external_reference = ExternalReference(**properties)
    # Then it should have the properties set correctly
    for key, value in properties.items():
        assert getattr(external_reference, key) == value


def test_external_reference_should_convert_to_stix2_object():
    """Test that ExternalReference can convert to a STIX-like object."""
    # Given an ExternalReference instance
    external_reference = ExternalReference(
        source_name="example_source",
        url="https://example.com",
    )
    # When converting to a STIX-like object
    stix_object = external_reference.to_stix2_object()
    # Then the STIX-like object should have the correct properties
    assert isinstance(stix_object, stix2.v21.ExternalReference)


### TEST TLP MARKING


def test_tlp_marking_should_be_a_base_entity():
    """Test that TLPMarking is a BaseEntity."""
    # Given the TLPMarking class
    # When checking the class inheritance
    # Then it should be a subclass of BaseEntity
    assert issubclass(TLPMarking, BaseEntity)


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


### TEST MODEL REGISTRY
def test_model_registry_should_register_models():
    """Test that MODEL_REGISTRY registers models correctly."""
    # Given the MODEL_REGISTRY
    registry = _ModelRegistry()

    # When registering a model
    class DummyModel(BaseEntity):
        def to_stix2_object(self) -> stix2.v21._STIXBase21:
            return stix2.v21._STIXBase21()

    registry.register(DummyModel)
    # Then it should be registered
    assert "DummyModel" in registry.models.keys()
    assert registry.models["DummyModel"] is DummyModel


def test_model_registry_should_be_a_singleton():
    """Test that MODEL_REGISTRY returns the same instance."""
    # Given the MODEL_REGISTRY
    registry1 = _ModelRegistry()
    # When getting the MODEL_REGISTRY again
    registry2 = _ModelRegistry()
    # Then it should return the same instance
    assert registry1 is registry2
    assert id(registry1) == id(registry2)
