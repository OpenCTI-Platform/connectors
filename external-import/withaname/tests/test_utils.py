from connector.utils import group_targets_by_host, is_valid_ipv4, normalize_host


def test_is_valid_ipv4():
    assert is_valid_ipv4("1.2.3.4") is True
    assert is_valid_ipv4(" 1.2.3.4 ") is True
    assert is_valid_ipv4("256.256.256.256") is False
    assert is_valid_ipv4("not-an-ip") is False
    assert is_valid_ipv4(None) is False
    assert is_valid_ipv4("") is False


def test_normalize_host():
    assert normalize_host("EXAMPLE.COM") == "example.com"
    assert normalize_host("  example.com  ") == "example.com"
    assert normalize_host("http://example.com/path") == "example.com"
    assert normalize_host("example.com:443") == "example.com"
    assert normalize_host(None) == ""
    assert normalize_host(123) == ""


def test_group_targets_by_host():
    targets = [
        {"host": "example.com", "ip": "1.1.1.1"},
        {"host": "example.com", "ip": "1.1.1.2"},
        {"host": "example.com", "ip": "1.1.1.1"},  # Duplicate IP
        {"host": "google.com", "ip": "8.8.8.8"},
        {"host": "invalid", "ip": "not-an-ip"},  # Invalid IP
        {"host": None, "ip": "1.1.1.1"},  # No host
    ]

    result = group_targets_by_host(targets)

    assert "example.com" in result
    assert "google.com" in result
    assert len(result["example.com"]["ips"]) == 2
    assert "1.1.1.1" in result["example.com"]["ips"]
    assert "1.1.1.2" in result["example.com"]["ips"]
    assert len(result["google.com"]["ips"]) == 1
    assert "8.8.8.8" in result["google.com"]["ips"]
    assert "invalid" in result
    assert len(result["invalid"]["ips"]) == 0
    assert "None" not in result
