"""
Unit tests for connector.indicator_pattern.

The patterns built here must match the ones OpenCTI generates when it promotes an
observable to an indicator: an indicator's deterministic ID is derived from its
pattern alone, so a pattern that differs by even a space creates a second entity
instead of upserting onto the promoted one. These tests pin the exact strings.
"""

import pytest
from connector.hive_observable_transform import (
    HiveObservableTransform,
    UnsupportedIndicatorTypeError,
)
from connector.indicator_pattern import (
    build_pattern,
    main_observable_type,
    resolve_pattern_key_value,
)
from stix2 import File

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
IDENTITY_ID = "identity--a5f78c07-79e2-4e8a-b1dd-fa3e5e5f1a5c"


def _stix_observable(data_type, data):
    observable = {
        "dataType": data_type,
        "data": data,
        "message": "m",
        "tags": [],
        "ioc": True,
    }
    return HiveObservableTransform(observable, [], IDENTITY_ID).stix_observable


# ---------------------------------------------------------------------------
# Pattern strings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data_type,data,expected",
    [
        ("ip", "8.8.8.8", "[ipv4-addr:value = '8.8.8.8']"),
        ("ipv6", "2001:4860:4860::8888", "[ipv6-addr:value = '2001:4860:4860::8888']"),
        ("domain", "evil.example.com", "[domain-name:value = 'evil.example.com']"),
        ("fqdn", "bad.example.org", "[domain-name:value = 'bad.example.org']"),
        (
            "url",
            "http://evil.example.com/x",
            "[url:value = 'http://evil.example.com/x']",
        ),
        ("mail", "a@b.com", "[email-addr:value = 'a@b.com']"),
        ("mail_subject", "Urgent wire", "[email-message:subject = 'Urgent wire']"),
        ("filename", "evil.exe", "[file:name = 'evil.exe']"),
        ("other", "freeform text", "[text:value = 'freeform text']"),
        ("regexp", "ab+c", "[text:value = 'ab+c']"),
        ("user-agent", "curl/8.0", "[user-agent:value = 'curl/8.0']"),
        ("autonomous-system", "15169", "[autonomous-system:number = 15169]"),
    ],
)
def test_build_pattern_matches_the_platform_output(data_type, data, expected):
    assert build_pattern(_stix_observable(data_type, data)) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (MD5, f"[file:hashes.MD5 = '{MD5}']"),
        (SHA1, f"[file:hashes.'SHA-1' = '{SHA1}']"),
        (SHA256, f"[file:hashes.'SHA-256' = '{SHA256}']"),
    ],
)
def test_hash_patterns_quote_the_algorithm_the_way_stix2_does(value, expected):
    # MD5 is a bare path component while SHA-1/SHA-256 are quoted, because the
    # hyphen is not valid in an unquoted STIX object path.
    assert build_pattern(_stix_observable("hash", value)) == expected


def test_registry_key_pattern_escapes_backslashes():
    pattern = build_pattern(_stix_observable("registry", r"HKLM\Software\Evil"))
    assert pattern == r"[windows-registry-key:key = 'HKLM\\Software\\Evil']"


# ---------------------------------------------------------------------------
# Types with no pattern
# ---------------------------------------------------------------------------


def test_unmapped_observable_type_yields_no_pattern():
    # 'organisation' maps to an Identity SDO, not an SCO, so the platform never
    # promotes it either.
    assert build_pattern(_stix_observable("organisation", "ACME")) is None


def test_transform_rejects_a_hash_of_unknown_length_before_any_pattern():
    # check_hash_type() returns "unknown-hash" for a length it does not know,
    # and the transform refuses that data type outright -- such an observable
    # never reaches the pattern builder at all.
    with pytest.raises(UnsupportedIndicatorTypeError):
        _stix_observable("hash", "abc123")


def test_file_with_unrecognised_hash_algorithm_yields_no_pattern():
    # Defensive: a File carrying only an algorithm with no pattern key.
    assert build_pattern(File(hashes={"SHA-512": "a" * 128})) is None


def test_resolve_returns_none_pair_for_unmapped_type():
    assert resolve_pattern_key_value(_stix_observable("organisation", "ACME")) == (
        None,
        None,
    )


# ---------------------------------------------------------------------------
# Main observable type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data_type,data,expected",
    [
        ("ip", "8.8.8.8", "IPv4-Addr"),
        ("domain", "evil.example.com", "Domain-Name"),
        ("hash", MD5, "StixFile"),
        ("url", "http://x/y", "Url"),
        ("other", "text", "Text"),
    ],
)
def test_main_observable_type(data_type, data, expected):
    assert main_observable_type(_stix_observable(data_type, data)) == expected


def test_main_observable_type_is_none_for_unmapped_type():
    assert main_observable_type(_stix_observable("organisation", "ACME")) is None
