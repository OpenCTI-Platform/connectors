import pytest
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.note import Note
from pydantic import ValidationError
from stix2.v21 import Note as Stix2Note


def test_note_is_a_base_identified_entity():
    """Test that Note is a BaseIdentifiedEntity."""
    # Given the Note class
    # When checking its type
    # Then it should be a subclass of BaseIdentifiedEntity
    assert issubclass(Note, BaseIdentifiedEntity)


def test_note_class_should_not_accept_invalid_input():
    """Test that Note class should not accept invalid input."""
    # Given: An invalid input data for Note
    input_data = {
        "name": "Test note",
        "invalid_key": "invalid_value",
    }
    # When validating the note
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Note.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_note_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Note to_stix2_object method returns a valid STIX2.1 Note."""
    # Given: A valid Note instance
    note = Note(
        abstract="Test note",
        publication_date="2025-01-01T12:00:00Z",
        content="Test content",
        note_types=["Test note type"],
        objects=[fake_valid_organization_author],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = note.to_stix2_object()
    # Then: A valid STIX2.1 Note is returned
    assert isinstance(stix2_obj, Stix2Note)
    assert isinstance(stix2_obj, Stix2Note)
