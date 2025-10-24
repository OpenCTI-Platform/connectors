import pytest
from connectors_sdk.models.ipv4_address import IPV4Address
from pydantic import ValidationError
from stix2.v21 import IPv4Address as Stix2IPv4Address


def test_ip_v4_class_should_not_accept_invalid_input():
    """Test that IPV4Address class should not accept invalid input."""
    # Given: An invalid input data for IPV4Address
    input_data = {
        "value": "invalid_ip",
        "invalid_key": "invalid_value",
    }
    # When validating the ipv4 address
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        IPV4Address.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_ip_v4_address_to_stix2_object_returns_valid_stix_object():
    """Test that IPV4Address to_stix2_object method returns a valid STIX2.1 IPV4Address."""
    # Given: A valid IPV4Address instance
    ipv4_address = IPV4Address(value="0.0.0.0/24")  # explict test with CIDR notation
    # When: calling to_stix2_object method
    stix2_obj = ipv4_address.to_stix2_object()
    # Then: A valid STIX2.1 IPV4Address is returned
    assert isinstance(stix2_obj, Stix2IPv4Address)
