import pytest
import stix2
import stix2.properties
from connectors_sdk.models.associated_file import AssociatedFile, AssociatedFileStix
from connectors_sdk.models.base_object import BaseObject
from connectors_sdk.models.tlp_marking import TLPMarking


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
    """Test that AssociatedFile is a BaseObject."""
    # Given the AssociatedFile class
    # When checking the class inheritance
    # Then it should be a subclass of BaseObject
    assert issubclass(AssociatedFile, BaseObject)


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


def test_associated_file_to_stix2_object() -> None:
    """Test the to_stix2_object method of AssociatedFile."""
    # Given an AssociatedFile instance with all properties
    associated_file = AssociatedFile(
        name="example_file.txt",
        description="A sample file",
        content=b"Sample content",
        mime_type="text/plain",
        version="1.0",
    )
    assert associated_file.to_stix2_object() == AssociatedFileStix(
        name="example_file.txt",
        description="A sample file",
        data="U2FtcGxlIGNvbnRlbnQ=\n",  # Base64 encoded content
        mime_type="text/plain",
        version="1.0",
    )
