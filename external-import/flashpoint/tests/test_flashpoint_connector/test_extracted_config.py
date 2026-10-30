from flashpoint_connector.extracted_config import (
    NetworkIndicator,
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
        NetworkIndicator("domain", "example.com"),
        NetworkIndicator("ipv4", "203.0.113.10"),
        NetworkIndicator("ipv6", "2001:db8::1"),
        NetworkIndicator("url", "http://example.org/x"),
    ]


def test_extract_network_indicators_should_read_c2s_keys_whatever_the_case():
    config = {"C2s": ["http://203.0.113.5/a"], "c2s": "http://198.51.100.1/b"}

    assert extract_network_indicators(config) == [
        NetworkIndicator("url", "http://203.0.113.5/a"),
        NetworkIndicator("url", "http://198.51.100.1/b"),
    ]


def test_extract_network_indicators_should_reduce_url_without_path_to_host():
    config = {
        "c2s": [
            "https://example.org",
            "https://example.net/",
            "http://203.0.113.7:8080",
            "https://example.com/gate",
            "https://example.com/?q=1",
        ]
    }

    assert extract_network_indicators(config) == [
        NetworkIndicator("domain", "example.org"),
        NetworkIndicator("domain", "example.net"),
        NetworkIndicator("ipv4", "203.0.113.7"),
        NetworkIndicator("url", "https://example.com/gate"),
        NetworkIndicator("url", "https://example.com/?q=1"),
    ]


def test_extract_network_indicators_should_flag_dga_keys():
    config = {
        "dga_c2s": ["https://dga.example.org"],
        "Hosts": ["dga.example.org", "other.example.org"],
    }

    assert extract_network_indicators(config) == [
        NetworkIndicator("domain", "dga.example.org", True),
        NetworkIndicator("domain", "other.example.org", False),
    ]


def test_extract_parameters_should_drop_network_keys_and_empty_values():
    config = {
        "Hosts": ["example.com"],
        "Ports": "443,80",
        "Group": "",
        "Plugin": None,
        "list": ["a", "b"],
    }

    assert extract_parameters(config) == {"list": "a, b", "Ports": "443,80"}


def test_extract_parameters_should_be_independent_of_order():
    first = {"b": ["y", "x"], "A": "1"}
    second = {"A": "1", "b": ["x", "y"]}

    assert extract_parameters(first) == extract_parameters(second)
    assert list(extract_parameters(first)) == ["A", "b"]
