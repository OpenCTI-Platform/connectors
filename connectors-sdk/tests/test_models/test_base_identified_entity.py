from typing import OrderedDict

import pytest
import stix2
import stix2.properties
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.base_object import BaseObject
from connectors_sdk.models.enums import ExtensionDefinitionId, ExtensionType
from pycti import STIX_EXT_OCTI, STIX_EXT_OCTI_SCO
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


def test_base_identified_entity_should_accept_reference_object_for_author_and_markings(
    implemented_base_identified_entity,
    fake_valid_reference,
    fake_valid_reference_with_tlp_id,
):
    """Test that BaseIdentifiedEntity with reference objects."""
    # Given an implemented BaseIdentifiedEntity
    entity_class = implemented_base_identified_entity
    entity_instance = entity_class(
        toto="toto",
        author=fake_valid_reference,
        markings=[fake_valid_reference_with_tlp_id],
    )
    # Then author and marking should be a Reference model
    assert entity_instance.author == fake_valid_reference
    assert entity_instance.markings == [fake_valid_reference_with_tlp_id]


def test_base_identified_entity_common_stix2_properties_includes_created(
    implemented_base_identified_entity,
):
    """Test that _common_stix2_properties includes created when set."""
    entity = implemented_base_identified_entity(
        toto="toto",
        created="2024-01-01T00:00:00Z",
    )
    props = entity._common_stix2_properties()
    assert props["created"] is not None


def test_base_identified_entity_common_stix2_properties_includes_created_as_none(
    implemented_base_identified_entity,
):
    """Test that _common_stix2_properties includes created as None when not set."""
    entity = implemented_base_identified_entity(toto="toto")
    props = entity._common_stix2_properties()
    assert "created" in props
    assert props["created"] is None


def test_base_identified_entity_common_properties_have_no_extension(
    implemented_base_identified_entity,
):
    """Test that the common properties have no extension and no x_opencti_* property."""
    # Given an implemented BaseIdentifiedEntity
    entity = implemented_base_identified_entity(toto="toto")
    # When getting the common properties
    properties = entity._common_stix2_properties()
    # Then there is no extension and no x_opencti_* property
    assert "extensions" not in properties
    assert not [key for key in properties if key.startswith("x_opencti_")]


def test_custom_stix2_extensions_writes_properties_in_extension(
    implemented_base_identified_entity,
):
    """Test that the OpenCTI properties go in a property extension, without empty values."""
    # Given an implemented BaseIdentifiedEntity
    entity = implemented_base_identified_entity(toto="toto")
    # When getting the extensions for OpenCTI properties
    extensions = entity._custom_stix2_extensions(
        ExtensionDefinitionId.OCTI,
        extension_type=ExtensionType.PROPERTY_EXTENSION,
        properties={
            "reliability": "A",
            "aliases": ["alias"],
            "score": 0,
            "location_type": None,
            "cwe": [],
        },
    )
    # Then the extension holds the non-empty properties, like OpenCTI exports
    assert extensions == {
        "extensions": {
            STIX_EXT_OCTI: {
                "extension_type": "property-extension",
                "reliability": "A",
                "aliases": ["alias"],
                "score": 0,
            }
        }
    }


def test_custom_stix2_extensions_new_type_only_gives_its_type(
    implemented_base_identified_entity,
):
    """Test that an extension that defines a new type only gives its type."""
    # Given an implemented BaseIdentifiedEntity
    entity = implemented_base_identified_entity(toto="toto")
    # When getting the extensions of a new-sco type
    extensions = entity._custom_stix2_extensions(
        ExtensionDefinitionId.OCTI_SCO, extension_type=ExtensionType.NEW_SCO
    )
    # Then the extension only gives its type: the properties go at the top level
    assert extensions == {
        "extensions": {STIX_EXT_OCTI_SCO: {"extension_type": "new-sco"}}
    }


def test_custom_stix2_extensions_property_extension_needs_properties(
    implemented_base_identified_entity,
):
    """Test that a property extension without properties is refused."""
    # Given an implemented BaseIdentifiedEntity
    entity = implemented_base_identified_entity(toto="toto")
    # When getting a property extension without properties
    # Then a ValueError is raised
    with pytest.raises(ValueError, match="needs properties"):
        entity._custom_stix2_extensions(
            ExtensionDefinitionId.OCTI,
            extension_type=ExtensionType.PROPERTY_EXTENSION,
        )


def test_custom_stix2_extensions_new_type_refuses_properties(
    implemented_base_identified_entity,
):
    """Test that an extension that defines a new type refuses properties."""
    # Given an implemented BaseIdentifiedEntity
    entity = implemented_base_identified_entity(toto="toto")
    # When getting a new-sco extension with properties
    # Then a ValueError is raised
    with pytest.raises(ValueError, match="holds no properties"):
        entity._custom_stix2_extensions(
            ExtensionDefinitionId.OCTI_SCO,
            extension_type=ExtensionType.NEW_SCO,
            properties={"score": 1},
        )


def test_deprecated_x_opencti_properties(implemented_base_identified_entity):
    """Test that the OpenCTI properties are also given as x_opencti_* properties."""
    # Given an implemented BaseIdentifiedEntity
    entity = implemented_base_identified_entity(toto="toto")
    # When getting the deprecated properties for OpenCTI properties
    properties = entity._deprecated_x_opencti_properties(
        {"reliability": "A", "score": 0, "location_type": None}
    )
    # Then they are the same properties, with the x_opencti_ prefix
    # (stix2 drops the empty ones at the top level)
    assert properties == {
        "x_opencti_reliability": "A",
        "x_opencti_score": 0,
        "x_opencti_location_type": None,
    }


def test_merge_stix2_properties_merges_extensions(implemented_base_identified_entity):
    """Test that the merge combines the extensions instead of replacing them."""
    # Given properties with extensions, some with the same extension id
    first = {
        "name": "name",
        "extensions": {
            STIX_EXT_OCTI: {"extension_type": "property-extension", "score": 1}
        },
    }
    second = {
        "extensions": {
            STIX_EXT_OCTI: {"extension_type": "property-extension", "aliases": ["a"]},
            "extension-definition--other": {"extension_type": "property-extension"},
        },
        "x_opencti_score": 1,
        "x_opencti_aliases": ["a"],
    }
    # When merging them
    merged = implemented_base_identified_entity._merge_stix2_properties(first, second)
    # Then the extensions are merged
    assert merged == {
        "name": "name",
        "x_opencti_score": 1,
        "x_opencti_aliases": ["a"],
        "extensions": {
            STIX_EXT_OCTI: {
                "extension_type": "property-extension",
                "score": 1,
                "aliases": ["a"],
            },
            "extension-definition--other": {"extension_type": "property-extension"},
        },
    }


def test_merge_stix2_properties_without_extension(implemented_base_identified_entity):
    """Test that the merge adds no extension when there is none."""
    # Given properties without extension
    # When merging them
    merged = implemented_base_identified_entity._merge_stix2_properties(
        {"name": "name"}, {"labels": ["label"]}
    )
    # Then there is no extension
    assert merged == {"name": "name", "labels": ["label"]}


@pytest.mark.parametrize(
    "first, second, message",
    [
        pytest.param(
            {"name": "a"},
            {"name": "b"},
            "'name' is given twice with different values",
            id="top_level_conflict",
        ),
        pytest.param(
            {"extensions": {STIX_EXT_OCTI: {"score": 1}}},
            {"extensions": {STIX_EXT_OCTI: {"score": 2}}},
            "'score' of .* different values",
            id="extension_conflict",
        ),
    ],
)
def test_merge_stix2_properties_rejects_duplicates(
    implemented_base_identified_entity, first, second, message
):
    """Test that the merge refuses a property given twice with different values."""
    # Given properties that give the same property twice, with different values
    # When merging them
    # Then a ValueError is raised
    with pytest.raises(ValueError, match=message):
        implemented_base_identified_entity._merge_stix2_properties(first, second)


def test_merge_stix2_properties_accepts_same_value_twice(
    implemented_base_identified_entity,
):
    """Test that a property given twice with the same value is accepted."""
    # Given properties that give the same property twice, with the same value
    # When merging them
    merged = implemented_base_identified_entity._merge_stix2_properties(
        {"x_opencti_score": 1, "extensions": {STIX_EXT_OCTI: {"score": 1}}},
        {"x_opencti_score": 1, "extensions": {STIX_EXT_OCTI: {"score": 1}}},
    )
    # Then the property is kept once
    assert merged == {"x_opencti_score": 1, "extensions": {STIX_EXT_OCTI: {"score": 1}}}


@pytest.mark.parametrize(
    "properties",
    [
        pytest.param(
            {
                "extensions": {STIX_EXT_OCTI: {"score": 1}},
                "x_opencti_score": 1,
            },
            id="extension",
        ),
        pytest.param(
            {
                "extensions": {STIX_EXT_OCTI: {"cvss_vector": "AV:N"}},
                "x_opencti_cvss_vector_string": "AV:N",
            },
            id="renamed",
        ),
        pytest.param(
            {"x_opencti_files": [], "x_opencti_create_indicator": True},
            id="top_level_only",
        ),
        pytest.param({"x_opencti_score": None}, id="empty"),
        pytest.param(
            {"extensions": {STIX_EXT_OCTI: {"score": 0}}, "x_opencti_score": 0},
            id="falsy_value",
        ),
        pytest.param(
            {"extensions": {"extension-definition--other": {"score": 1}}},
            id="not_an_opencti_extension",
        ),
    ],
)
def test_check_deprecated_x_opencti_properties_accepts(
    implemented_base_identified_entity, properties
):
    """Test that matching OpenCTI properties and their known exceptions are accepted."""
    # Given consistent properties
    # When checking them
    # Then no error is raised
    implemented_base_identified_entity._check_deprecated_x_opencti_properties(
        properties
    )


@pytest.mark.parametrize(
    "properties, message",
    [
        pytest.param(
            {"extensions": {STIX_EXT_OCTI: {"score": 1}}, "x_opencti_score": 2},
            "'score' is `1` in the OpenCTI extension, but 'x_opencti_score' is `2`",
            id="different_values",
        ),
        pytest.param(
            {"x_opencti_score": 1},
            "'x_opencti_score' is `1`, but it is not in an OpenCTI extension",
            id="not_in_extension",
        ),
        pytest.param(
            {"extensions": {STIX_EXT_OCTI: {"score": 1}}},
            "'score' is `1` in the OpenCTI extension, but 'x_opencti_score' is `None`",
            id="missing_copy",
        ),
    ],
)
def test_check_deprecated_x_opencti_properties_rejects(
    implemented_base_identified_entity, properties, message
):
    """Test that an OpenCTI property missing or different in one of its places is refused."""
    # Given inconsistent properties
    # When checking them
    # Then a ValueError is raised
    with pytest.raises(ValueError, match=message):
        implemented_base_identified_entity._check_deprecated_x_opencti_properties(
            properties
        )
