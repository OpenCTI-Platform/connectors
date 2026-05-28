import pytest
from connectors_sdk.models.file import File
from pydantic import ValidationError
from stix2.v21 import File as Stix2File


def test_file_class_should_not_accept_invalid_input():
    """Test that File class should not accept invalid input."""
    # Given: An invalid input data for File
    input_data = {
        "value": "invalid_ip",
        "invalid_key": "invalid_value",
    }
    # When validating the file
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        File.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_file_should_not_accept_missing_name_and_missing_hashes():
    """Test that File should not accept both missing name and missing hashes."""
    # Given an invalid input data for File with no name nor hashes
    input_data = {"mime_type": "text/plain"}
    # When validating the file
    # Then it should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        _ = File.model_validate(input_data)
        assert all(w in str(error.value.errors()[0]) for w in ("'name'", "'hashes'"))


def test_file_to_stix2_object_returns_valid_stix_object():
    """Test that File to_stix2_object method returns a valid STIX2.1 File."""
    # Given: A valid File instance
    file = File(name="test.txt")
    # When: calling to_stix2_object method
    stix2_obj = file.to_stix2_object()
    # Then: A valid STIX2.1 File is returned
    assert isinstance(stix2_obj, Stix2File)
