import pytest
from connectors_sdk.models.email_address import EmailAddress
from pydantic import ValidationError
from stix2.v21 import EmailAddress as Stix2EmailAddress


def test_email_address_class_should_not_accept_invalid_input():
    """Test that EmailAddress class should not accept invalid input."""
    input_data = {
        "value": "user@example.com",
        "invalid_key": "invalid_value",
    }
    with pytest.raises(ValidationError) as error:
        EmailAddress.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_email_address_to_stix2_object_returns_valid_stix_object():
    """Test that EmailAddress to_stix2_object method returns a valid STIX2.1 object."""
    email_address = EmailAddress(value="user@example.com")
    stix2_obj = email_address.to_stix2_object()
    assert isinstance(stix2_obj, Stix2EmailAddress)
