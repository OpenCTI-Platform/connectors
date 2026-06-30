import pytest
from connector.utils import check_hash_type, format_datetime, is_ipv4, is_ipv6


def test_format_datetime_epoch_zero():
    assert format_datetime(0, "%Y-%m-%dT%H:%M:%SZ") == "1970-01-01T00:00:00Z"


def test_format_datetime_known_timestamp():
    # 2023-01-01 00:00:00 UTC
    assert format_datetime(1672531200, "%Y-%m-%dT%H:%M:%SZ") == "2023-01-01T00:00:00Z"


def test_format_datetime_custom_format():
    result = format_datetime(1672531200, "%Y-%m-%d")
    assert result == "2023-01-01"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2001:db8::1", True),
        ("::1", True),
        ("2001:db8::/32", True),
        ("192.168.1.1", False),
        ("not-an-ip", False),
        ("", False),
    ],
)
def test_is_ipv6(value, expected):
    assert is_ipv6(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("192.168.1.1", True),
        ("10.0.0.0/8", True),
        ("0.0.0.0", True),
        ("2001:db8::1", False),
        ("not-an-ip", False),
        ("", False),
        ("999.999.999.999", False),
    ],
)
def test_is_ipv4(value, expected):
    assert is_ipv4(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("a" * 32, "MD5"),
        ("b" * 40, "SHA-1"),
        ("c" * 64, "SHA-256"),
        ("d" * 10, "unknown-hash"),
        ("e" * 128, "unknown-hash"),
    ],
)
def test_check_hash_type(value, expected):
    assert check_hash_type(value) == expected
