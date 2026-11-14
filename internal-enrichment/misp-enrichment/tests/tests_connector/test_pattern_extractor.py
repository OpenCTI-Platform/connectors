import pytest
from connector.pattern_extractor import extract_values_from_pattern


@pytest.mark.parametrize(
    "pattern, expected",
    [
        pytest.param("[ipv4-addr:value = '1.2.3.4']", ["1.2.3.4"], id="ipv4"),
        pytest.param("[ipv6-addr:value = '2001:db8::1']", ["2001:db8::1"], id="ipv6"),
        pytest.param("[domain-name:value = 'evil.com']", ["evil.com"], id="domain"),
        pytest.param(
            "[url:value = 'http://evil.com/a?b=c']", ["http://evil.com/a?b=c"], id="url"
        ),
        pytest.param(
            "[email-addr:value = 'bad@evil.com']", ["bad@evil.com"], id="email"
        ),
        pytest.param("[file:hashes.MD5 = 'abc']", ["abc"], id="md5_unquoted"),
        pytest.param("[file:hashes.'SHA-256' = 'def']", ["def"], id="sha256_quoted"),
        pytest.param(
            "[file:hashes.\"SHA-1\" = 'ghi']", ["ghi"], id="sha1_double_quoted"
        ),
        pytest.param("[file:hashes.'SHA-512'='jkl']", ["jkl"], id="sha512_no_spaces"),
        pytest.param(
            "[ipv4-addr:value = '1.2.3.4'] OR [file:hashes.MD5 = 'abc'] OR [ipv4-addr:value = '1.2.3.4']",
            ["1.2.3.4", "abc"],
            id="several_values_deduplicated",
        ),
        pytest.param(
            "[url:value = 'http://evil.com/it\\'s']",
            ["http://evil.com/it's"],
            id="escaped_quote",
        ),
        pytest.param("[file:name = 'evil.exe']", [], id="unsupported_path"),
        pytest.param("[network-traffic:dst_port = 443]", [], id="no_string_value"),
        pytest.param("", [], id="empty_pattern"),
    ],
)
def test_extract_values_from_pattern(pattern, expected):
    assert extract_values_from_pattern(pattern) == expected
