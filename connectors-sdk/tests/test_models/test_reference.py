import pytest
from connectors_sdk.models.reference import Reference
from pydantic import ValidationError


def test_reference_class_should_not_accept_invalid_type_input():
    """Test that Reference class should not accept invalid type input."""
    # Given: An invalid input data for Reference
    input_data = {
        "id": 12345,
    }
    # When validating the reference
    # Then: It should raise a ValidationError
    with pytest.raises(ValidationError) as error:
        Reference.model_validate(input_data)

    assert error.value.errors()[0]["loc"] == ("id",)
    assert error.value.errors()[0]["msg"] == "Input should be a valid string"


def test_reference_missing_required_field():
    """Test that missing required fields raise validation errors."""
    # Given: Reference data without the required id field
    invalid_data = {
        "invalid_input": "invalid data",
    }

    # When/Then: Creating a model should raise a validation error
    with pytest.raises(ValidationError) as error:
        Reference(**invalid_data)

    assert error.value.errors()[0]["loc"] == ("id",)
    assert error.value.errors()[0]["msg"] == "Field required"


def test_reference_returns_valid_object():
    """Test that Reference instanciation returns a valid object."""
    # Given: A valid Reference instance
    reference = Reference(
        id="id-12345",
    )
    # Then: A valid Reference is returned
    assert isinstance(reference, Reference)
