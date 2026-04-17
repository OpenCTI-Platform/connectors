from microsoft_sentinel_intel.utils import extract_pattern_type


def test_extract_pattern_type_ipv4():
    assert extract_pattern_type("[ipv4-addr:value = '1.1.1.1']") == "ipv4-addr"


def test_extract_pattern_type_domain():
    assert extract_pattern_type("[domain-name:value = 'evil.com']") == "domain-name"


def test_extract_pattern_type_file():
    assert extract_pattern_type("[file:hashes.MD5 = 'abc123']") == "file"


def test_extract_pattern_type_url():
    assert extract_pattern_type("[url:value = 'http://evil.com']") == "url"


def test_extract_pattern_type_ipv6():
    assert extract_pattern_type("[ipv6-addr:value = '::1']") == "ipv6-addr"


def test_extract_pattern_type_invalid():
    assert extract_pattern_type("not a pattern") is None


def test_extract_pattern_type_empty():
    assert extract_pattern_type("") is None


def test_extract_pattern_type_malformed():
    assert extract_pattern_type("[no-colon]") is None


def test_extract_pattern_type_compound_returns_first():
    """Compound patterns return only the first type (by design)."""
    assert (
        extract_pattern_type(
            "[ipv4-addr:value = '1.1.1.1'] OR [domain-name:value = 'evil.com']"
        )
        == "ipv4-addr"
    )
