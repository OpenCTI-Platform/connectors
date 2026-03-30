import pytest
from connectors_sdk.models import ExternalReference, OrganizationAuthor, TLPMarking
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.text import Text
from pycti import CustomObservableText
from pydantic import ValidationError


def test_text_is_a_base_observable_entity() -> None:
    """Test that Text is a BaseObservableEntity."""
    # Given the Text class
    # When checking its type
    # Then it should be a subclass of BaseObservableEntity
    assert issubclass(Text, BaseObservableEntity)


def test_text_is_a_base_identified_entity() -> None:
    """Test that Text is a BaseIdentifiedEntity."""
    # Given the Text class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Text, BaseIdentifiedEntity)


def test_text_class_should_not_accept_invalid_input() -> None:
    """Test that Text class should not accept invalid input."""
    # Given: An invalid input data for Text
    input_data = {
        "value": "some text",
        "invalid_key": "invalid_value",
    }
    # When validating the text
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Text.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_text_class_should_not_accept_empty_value() -> None:
    """Test that Text class should not accept an empty value."""
    # Given: An input with an empty string value
    input_data = {"value": ""}
    # When validating the text
    # Then: It should raise a ValidationError (min_length=1)
    with pytest.raises(ValidationError):
        Text.model_validate(input_data)


def test_text_to_stix2_object_returns_valid_stix_object() -> None:
    """Test that Text to_stix2_object method returns a valid CustomObservableText."""
    # Given: A valid Text instance
    text = Text(value="some extracted config value")
    # When: calling to_stix2_object method
    stix2_obj = text.to_stix2_object()
    # Then: A valid CustomObservableText is returned
    assert isinstance(stix2_obj, CustomObservableText)
    assert stix2_obj.value == "some extracted config value"


def test_text_to_stix2_object_has_deterministic_id() -> None:
    """Test that Text produces a deterministic STIX ID based on value."""
    # Given: Two Text instances with the same value
    text_a = Text(value="deterministic test")
    text_b = Text(value="deterministic test")
    # When: converting both to STIX objects
    stix_a = text_a.to_stix2_object()
    stix_b = text_b.to_stix2_object()
    # Then: They should have the same ID
    assert stix_a.id == stix_b.id
    assert stix_a.id.startswith("text--")


def test_text_to_stix2_object_with_different_values_have_different_ids() -> None:
    """Test that Text instances with different values produce different IDs."""
    # Given: Two Text instances with different values
    text_a = Text(value="value one")
    text_b = Text(value="value two")
    # When: converting both to STIX objects
    stix_a = text_a.to_stix2_object()
    stix_b = text_b.to_stix2_object()
    # Then: They should have different IDs
    assert stix_a.id != stix_b.id


def test_text_to_stix2_object_with_author_and_markings(
    fake_valid_organization_author: OrganizationAuthor,
    fake_valid_tlp_markings: list[TLPMarking],
    fake_valid_external_references: list[ExternalReference],
) -> None:
    """Test that Text to_stix2_object method includes author, markings, and external references."""
    # Given: A Text instance with author, markings, and external references
    text = Text(
        value="config value with metadata",
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = text.to_stix2_object()
    # Then: The STIX object should match with all custom properties
    assert stix2_obj == CustomObservableText(
        value="config value with metadata",
        allow_custom=True,
        object_marking_refs=[
            marking.to_stix2_object().id for marking in fake_valid_tlp_markings
        ],
        x_opencti_created_by_ref=fake_valid_organization_author.id,
        x_opencti_external_references=[
            external_ref.to_stix2_object()
            for external_ref in fake_valid_external_references
        ],
    )
