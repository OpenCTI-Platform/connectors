import pytest
from connectors_sdk.models.software import Software
from pydantic import ValidationError
from stix2.v21 import Software as Stix2Software


def test_software_class_should_not_accept_invalid_input():
    """Test that Software class should not accept invalid input."""
    # Given: An invalid input data for Software
    input_data = {
        "name": "Test software",
        "invalid_key": "invalid_value",
    }
    # When validating the software
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        Software.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_software_address_to_stix2_object_returns_valid_stix_object(
    fake_valid_organization_author,
    fake_valid_tlp_markings,
    fake_valid_external_references,
):
    """Test that Software to_stix2_object method returns a valid STIX2.1 Software."""
    # Given: A valid Software instance
    ipv4_address = Software(
        name="Test Software",
        description="Test software description",
        labels=["label_1", "label_2"],
        version="1.0.0",
        vendor="Test vendor",
        swid="Test SWID",
        cpe="cpe:/a:test:software:1.0.0",
        languages=["python"],
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
        external_references=fake_valid_external_references,
    )
    # When: calling to_stix2_object method
    stix2_obj = ipv4_address.to_stix2_object()
    # Then: A valid STIX2.1 Software is returned
    assert isinstance(stix2_obj, Stix2Software)
