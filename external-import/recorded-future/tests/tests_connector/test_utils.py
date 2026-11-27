import pytest
from rflib.utils import is_ip_v4_address, is_ip_v6_address


@pytest.mark.parametrize(
    "value, expected",
    [
        ("1.1.1.1", True),
        ("91.92.42.0/24", True),
        ("91.92.42.7/24", True),
        ("91.92.42.0/33", False),
        ("2001:db8::1", False),
        ("not-an-ip", False),
    ],
)
# Scenario: IPv4 addresses and ranges (CIDR) are recognized as IPv4 (issue #8487)
def test_is_ip_v4_address(value, expected):
    # Given a value
    # When checking whether it is an IPv4 address or range
    # Then IPv4 addresses and valid IPv4 ranges are accepted
    assert is_ip_v4_address(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2001:db8::1", True),
        ("2001:db8::/32", True),
        ("2001:db8::/129", False),
        ("1.1.1.1", False),
        ("not-an-ip", False),
    ],
)
# Scenario: IPv6 addresses and ranges (CIDR) are recognized as IPv6 (issue #8487)
def test_is_ip_v6_address(value, expected):
    # Given a value
    # When checking whether it is an IPv6 address or range
    # Then IPv6 addresses and valid IPv6 ranges are accepted
    assert is_ip_v6_address(value) is expected
