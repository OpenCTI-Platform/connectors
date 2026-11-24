import pytest
from connectors_sdk.models.file import File
from pycti import STIX_EXT_OCTI_SCO
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


def test_file_writes_additional_names_in_sco_extension():
    """Test that File writes its additional names in the SCO extension."""
    # Given a File with additional names
    file = File(name="test.txt", additional_names=["other.txt"])
    # When converting it to a STIX object
    stix2_obj = file.to_stix2_object()
    # Then the additional names are in the SCO extension and at the top level
    assert stix2_obj.extensions[STIX_EXT_OCTI_SCO] == {
        "extension_type": "property-extension",
        "additional_names": ["other.txt"],
    }
    assert stix2_obj.x_opencti_additional_names == ["other.txt"]


@pytest.mark.parametrize(
    "fields, expected_id",
    [
        pytest.param(
            {"name": "a.txt", "hashes": {"SHA-256": "a" * 64, "MD5": "b" * 32}},
            "file--f801efd2-7049-570a-b881-a0272716d1e6",
            id="md5_preferred_and_name",
        ),
        pytest.param(
            {"hashes": {"SHA-256": "a" * 64}},
            "file--75cb38d5-2055-5354-b75a-8299a2d670b5",
            id="sha256_only",
        ),
        pytest.param(
            {"name": "a.txt"},
            "file--a8a8ca77-e296-58b1-ae1d-6455bcb1014a",
            id="name_only",
        ),
        pytest.param(
            {"hashes": {"SHA3-256": "c" * 64, "SHA-512": "d" * 128}},
            "file--b4085862-e239-5786-85ca-3402487e6bec",
            id="sha512_preferred",
        ),
        pytest.param(
            {"hashes": {"SSDEEP": "3:abc:def"}},
            "file--8960510c-743a-5439-85c7-8b9924021936",
            id="other_hash_only",
        ),
        pytest.param(
            {"hashes": {"SHA-1": "e" * 40}, "name": "b.bin"},
            "file--3f67425c-26c0-5582-9782-1e589fd92299",
            id="sha1_and_name",
        ),
    ],
)
def test_file_id_does_not_depend_on_opencti_properties(fields, expected_id):
    """Test that a File keeps the id computed from its hashes and name only.

    stix2 also counts "extensions" in the File id. The expected ids are the ones
    the SDK produced before the OpenCTI extension.
    """
    # Given a File with OpenCTI properties, including File ones
    file = File(**fields, score=50, labels=["test"], additional_names=["c.txt"])
    # When getting its id
    # Then it is the id computed from its hashes and name only
    assert file.id == expected_id
    assert file.to_stix2_object().id == expected_id
