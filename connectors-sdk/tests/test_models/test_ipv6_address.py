import pytest
from connectors_sdk.models.ipv6_address import IPV6Address
from pydantic import ValidationError
from stix2.v21 import IPv6Address as Stix2IPv6Address


def test_ip_v6_class_should_not_accept_invalid_input():
    """Test that IPV6Address class should not accept invalid input."""
    # Given: An invalid input data for IPV6Address
    input_data = {
        "value": "invalid_ip",
        "invalid_key": "invalid_value",
    }
    # When validating the ipv6 address
    # Then: It should raise a ValidationError with the expected error field
    with pytest.raises(ValidationError) as error:
        IPV6Address.model_validate(input_data)
        assert error.value.errors()[0]["loc"] == ("invalid_key",)


def test_ip_v6_address_to_stix2_object_returns_valid_stix_object():
    """Test that IPV6Address to_stix2_object method returns a valid STIX2.1 IPV6Address."""
    # Given: A valid IPV6Address instance
    ipv6_address = IPV6Address(value="b357:5b10:0f48:d182:0140:494c:8fe9:6eda")
    # When: calling to_stix2_object method
    stix2_obj = ipv6_address.to_stix2_object()
    # Then: A valid STIX2.1 IPV6Address is returned
    assert isinstance(stix2_obj, Stix2IPv6Address)
