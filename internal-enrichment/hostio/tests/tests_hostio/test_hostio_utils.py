import pytest
from hostio.hostio_utils import (
    can_be_int,
    extract_asn_number,
    format_labels,
    get_tlp_marking,
    is_ipv4,
    is_ipv6,
    is_valid_token,
    lookup_tlp_string,
    validate_tlp_marking,
)
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE

VALID_IPV4 = "10.0.0.1"
VALID_IPV6 = "2001:db8::"
VALID_IPV4_CIDR = "10.0.0.0/24"
VALID_IPV6_CIDR = "2001:db8::/32"
INVALID_INPUT = ["", [], {}, None]


def test_is_ipv4():
    """Test is_ipv4() function."""
    assert is_ipv4(VALID_IPV4)


def test_is_ipv4_cidr():
    """Test is_ipv4() function with CIDR notation."""
    assert not is_ipv4(VALID_IPV4_CIDR)


def test_is_ipv4_false():
    """Test is_ipv4() function with IPv6 address."""
    assert not is_ipv4(VALID_IPV6)


def test_is_ipv4_invalid():
    """Test is_ipv4() function with invalid input."""
    for invalid in INVALID_INPUT:
        assert not is_ipv4(invalid)


def test_is_ipv6():
    """Test is_ipv6() function."""
    assert is_ipv6(VALID_IPV6)


def test_is_ipv6_cidr():
    """Test is_ipv6() function with CIDR notation."""
    assert not is_ipv6(VALID_IPV6_CIDR)


def test_is_ipv6_false():
    """Test is_ipv6() function with IPv4 address."""
    assert not is_ipv6(VALID_IPV4)


def test_is_ipv6_invalid():
    """Test is_ipv6() function with invalid input."""
    for invalid in INVALID_INPUT:
        assert not is_ipv6(invalid)


def test_is_valid_token():
    """Test is_valid_token() function."""
    assert is_valid_token("12345678901234")


def test_is_valid_token_false():
    """Test is_valid_token() function with invalid input."""
    for invalid in INVALID_INPUT:
        assert not is_valid_token(invalid)


def test_get_tlp_marking():
    """Test get_tlp_marking() function."""
    assert get_tlp_marking("TLP:WHITE") == TLP_WHITE
    assert get_tlp_marking("TLP:GREEN") == TLP_GREEN
    assert get_tlp_marking("TLP:AMBER") == TLP_AMBER
    assert get_tlp_marking("TLP:RED") == TLP_RED


def test_get_tlp_marking_invalid():
    """Test get_tlp_marking() function with invalid input."""
    for invalid in INVALID_INPUT:
        with pytest.raises(ValueError):
            get_tlp_marking(invalid)


def test_format_labels():
    """Test format_labels() function."""
    assert format_labels("hostio") == ["hostio"]
    assert format_labels(["hostio"]) == ["hostio"]
    assert format_labels(["hostio", "test"]) == ["hostio", "test"]
    assert format_labels("hostio,test") == ["hostio", "test"]


def test_format_labels_invalid():
    """Test format_labels() function with invalid input."""
    assert format_labels("") == []
    assert format_labels([]) == []
    """raise error when format_labels is {}"""
    with pytest.raises(ValueError):
        format_labels({})
    with pytest.raises(ValueError):
        format_labels(None)


def test_can_be_int():
    """Test can_be_int() function."""
    assert can_be_int("1")
    assert can_be_int(1)
    assert can_be_int("0")
    assert can_be_int(0)


def test_can_be_int_invalid():
    """Test can_be_int() function with invalid input."""
    assert not can_be_int("1.0")
    assert not can_be_int("")
    assert not can_be_int([])
    assert not can_be_int({})
    assert not can_be_int(None)
    assert not can_be_int(True)
    assert not can_be_int(False)
    assert not can_be_int(1.0)


def test_validate_tlp_marking():
    """Test velidate_tlp_marking() function."""
    assert get_tlp_marking("TLP:WHITE") == TLP_WHITE
    assert get_tlp_marking("TLP:GREEN") == TLP_GREEN
    assert get_tlp_marking("TLP:AMBER") == TLP_AMBER
    assert get_tlp_marking("TLP:RED") == TLP_RED


def test_validate_tlp_marking_invalid():
    """Test velidate_tlp_marking() function with invalid input."""
    for invalid in INVALID_INPUT:
        with pytest.raises(ValueError):
            validate_tlp_marking(invalid)


def test_validate_labels():
    """Test validate_labels() function."""
    assert format_labels("hostio") == ["hostio"]
    assert format_labels(["hostio"]) == ["hostio"]
    assert format_labels(["hostio", "test"]) == ["hostio", "test"]
    assert format_labels("hostio,test") == ["hostio", "test"]


def test_validate_labels_invalid():
    """Test validate_labels() function with invalid input."""
    assert format_labels("") == []
    assert format_labels([]) == []
    """raise error when format_labels is {}"""
    with pytest.raises(ValueError):
        format_labels({})
    with pytest.raises(ValueError):
        format_labels(None)


def test_extract_asn_number():
    """Test extract_asn_number() function."""
    VALID_ASN = "AS15169"
    assert extract_asn_number(VALID_ASN) == 15169
    VALID_ASN_2 = "ASN15169"
    assert extract_asn_number(VALID_ASN_2) == 15169


def test_extract_asn_number_invalid():
    """Test extract_asn_number() function with invalid input."""
    for invalid in INVALID_INPUT:
        assert extract_asn_number(invalid) is None


def test_lookup_tlp_string():
    """Test lookup_tlp_string() function."""
    assert lookup_tlp_string(TLP_WHITE) == "TLP:WHITE"
    assert lookup_tlp_string(TLP_GREEN) == "TLP:GREEN"
    assert lookup_tlp_string(TLP_AMBER) == "TLP:AMBER"
    assert lookup_tlp_string(TLP_RED) == "TLP:RED"


def test_lookup_tlp_string_invalid():
    """Test lookup_tlp_string() function with invalid input."""
    assert lookup_tlp_string("") is None
    assert lookup_tlp_string(True) is None
    assert lookup_tlp_string(False) is None
    assert lookup_tlp_string({}) is None
    assert lookup_tlp_string([]) is None
