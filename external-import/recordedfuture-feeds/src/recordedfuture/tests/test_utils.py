import hashlib
import ipaddress 
import random
import pytest
from recordedfuture.core.utils import (
    identify_hash,
    is_ipv4,
    is_ipv6,
    validate_required_keys
)

HASH_SEED = "HASHSEED".encode()
HASH_TYPES  = [
    'md5',
    'sha1',
    'sha256',
    'sha512',
    'sha3_256',
    'sha3_512'
]

HASH_TYPES_NONE = [
    'md5',
    'sha1'
]

HASH_TYPES_UNSUPPORTED = [
    'CRC-32',
    'SHA-384'
]

DATETIME_FORMATS = [
    '2023-09-26',
    '1695772799000',
    '2021-11-07T03:45:03.341Z'
]

## https://stackoverflow.com/a/56527053
MAX_IPV4 = ipaddress.IPv4Address._ALL_ONES  # 2 ** 32 - 1
MAX_IPV6 = ipaddress.IPv6Address._ALL_ONES  # 2 ** 128 - 1

def random_ipv4():
    return  ipaddress.IPv4Address._string_from_ip_int(
        random.randint(0, MAX_IPV4)
    )

def random_ipv6():
    return ipaddress.IPv6Address._string_from_ip_int(
        random.randint(0, MAX_IPV6)
    )
## end stackoverflow 

def test_identify_hash():
    """
        Iterates through HASH_TYPES and validates they are identified successfully. 
    """
    for hash_type in HASH_TYPES:
        hash_object = hashlib.new(hash_type)
        hash_object.update(HASH_SEED)
        known_identify_hash = identify_hash(
            hash_value=hash_object.hexdigest(),
            hash_type=hash_type
            )
        assert known_identify_hash != "Unknown"
        
def test_identify_hash_unsupporter():
    for hash_type in HASH_TYPES_UNSUPPORTED:
        unsupported_identify_hash = identify_hash(
            hash_value='NOT_A_HASH_VALUE',
            hash_type=hash_type
            )
        assert unsupported_identify_hash is "Unsupported"
        
def test_identify_hash_unknown():
    unknown_identify_hash = identify_hash("NOT_A_VALID_HASHTYPE","NOT_A_HASH_VALUE")
    assert unknown_identify_hash is "Unknown"

def test_identify_hash_none():
    for hash_type in HASH_TYPES_NONE:
        hash_object = hashlib.new(hash_type)
        hash_object.update(HASH_SEED)
        known_identify_hash = identify_hash(
            hash_value=hash_object.hexdigest()
            )
        assert known_identify_hash != "Unknown"

def test_is_ipv4():
    assert is_ipv4(random_ipv4())
    assert not is_ipv4(random_ipv6())

def test_is_ipv6():
    assert is_ipv6(random_ipv6())
    assert not is_ipv6(random_ipv4())

def test_validate_required_keys():
    data_entry = {
        "key1": "value1",
        "key2": "value2",
        "key3": "value3",
    }
    required_keys = ["key1", "key2"]

    # Test when all required keys are present
    try:
        validate_required_keys(data_entry, required_keys)
    except ValueError:
        pytest.fail("validate_required_keys raised ValueError unexpectedly!")

    # Test when one required key is missing
    required_keys_missing_one = ["key1", "key4"]
    assert not validate_required_keys(data_entry, required_keys_missing_one)

    # Test when multiple required keys are missing
    required_keys_missing_multiple = ["key1", "key4", "key5"]
    assert not validate_required_keys(data_entry, required_keys_missing_multiple)
