from flashpoint_connector.extracted_config import (
    extract_network_indicators,
    extract_parameters,
    parse_extracted_config,
)


def test_parse_extracted_config_should_return_dict_only():
    assert parse_extracted_config('{"a": 1}') == {"a": 1}
    assert parse_extracted_config("[1]") is None
    assert parse_extracted_config("nope") is None
    assert parse_extracted_config(None) is None


def test_extract_network_indicators_should_classify_and_deduplicate():
    config = {
        "Hosts": ["Example.com", "203.0.113.10"],
        "Domains": "example.com,,2001:db8::1",
        "urls": "http://example.org/x",
        "Mutex": "example.net",
    }

    assert extract_network_indicators(config) == [
        ("domain", "example.com"),
        ("ipv4", "203.0.113.10"),
        ("ipv6", "2001:db8::1"),
        ("url", "http://example.org/x"),
    ]


def test_extract_parameters_should_drop_network_keys_and_empty_values():
    config = {
        "Hosts": ["example.com"],
        "Ports": "443,80",
        "Group": "",
        "Plugin": None,
        "list": ["a", "b"],
    }

    assert extract_parameters(config) == {"Ports": "443,80", "list": "a, b"}
