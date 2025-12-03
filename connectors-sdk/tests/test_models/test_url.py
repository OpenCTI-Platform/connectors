import pytest
from connectors_sdk.models.url import URL
from pydantic import ValidationError
from stix2.v21 import URL as Stix2URL


def test_url_class_should_not_accept_invalid_input():
    """Test that URL class should not accept invalid input."""
    # Given: An invalid input data for URL
    input_data = {
        "value": "invalid_ip",
        "invalid_key": "invalid_value",
    }
    # When validating the url
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        URL.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_url_to_stix2_object_returns_valid_stix_object():
    """Test that URL to_stix2_object method returns a valid STIX2.1 URL."""
    # Given: A valid URL instance
    domain_name = URL(value="test.com")
    # When: calling to_stix2_object method
    stix2_obj = domain_name.to_stix2_object()
    # Then: A valid STIX2.1 URL is returned
    assert isinstance(stix2_obj, Stix2URL)
