import warnings

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
    # Given: A valid Note instance using 'created' (new way)
    note = Note(
        abstract="Test note",
        created="2025-01-01T12:00:00Z",
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


def test_note_to_stix2_object_with_publication_date_emits_deprecation_warning(
    fake_valid_organization_author,
    fake_valid_external_references,
    fake_valid_tlp_markings,
):
    """Test that Note with publication_date emits a deprecation warning."""
    # Given/When: A Note using deprecated 'publication_date'
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
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
        # Then: A deprecation warning is emitted
        deprecation_warnings = [
            x for x in w if issubclass(x.category, DeprecationWarning)
        ]
        assert len(deprecation_warnings) == 1
        assert "publication_date" in str(deprecation_warnings[0].message)

    # And: to_stix2_object still works
    stix2_obj = note.to_stix2_object()
    assert isinstance(stix2_obj, Stix2Note)


def test_note_raises_error_if_both_publication_date_and_created_are_set():
    """Test that Note raises an error if both publication_date and created are set."""
    # Given: Both publication_date and created are provided
    # When/Then: A ValidationError is raised
    with pytest.raises(ValidationError) as error:
        Note(
            content="Test content",
            publication_date="2025-01-01T12:00:00Z",
            created="2025-02-01T12:00:00Z",
        )
    assert "publication_date" in str(error.value)
    assert "created" in str(error.value)


def test_note_to_stix2_object_returns_valid_stix_object_with_reference_object(
    fake_valid_reference,
):
    """Test that Note to_stix2_object method returns a valid STIX2.1 Note with reference object."""
    # Given: A valid Note instance
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        note = Note(
            publication_date="2025-01-01T12:00:00Z",
            content="Test content",
            objects=[fake_valid_reference],
        )
    # When: calling to_stix2_object method
    stix2_obj = note.to_stix2_object()
    # Then: A valid STIX2.1 Note is returned
    # object_refs should be a Reference model id
    assert isinstance(stix2_obj, Stix2Note)
    assert stix2_obj.object_refs == [fake_valid_reference.id]
