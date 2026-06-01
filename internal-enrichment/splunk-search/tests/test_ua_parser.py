from internal_enrichment_connector.ua_parser import ParsedUserAgent, UserAgentParser


def test_parse_chrome():
    parser = UserAgentParser()
    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )

    parsed = parser.parse(ua)
    assert parsed is not None
    assert parsed.software_name in {"Chrome", "Chromium"}


def test_parse_curl():
    parser = UserAgentParser()
    parsed = parser.parse("curl/8.4.0")

    assert parsed is not None
    assert parsed.software_name == "curl"
    assert parsed.software_version == "8.4.0"


def test_parse_python_requests():
    parser = UserAgentParser()
    parsed = parser.parse("python-requests/2.31.0")

    assert parsed is not None
    assert parsed.software_name == "python-requests"
    assert parsed.software_version == "2.31.0"


def test_parse_bot():
    parser = UserAgentParser()
    ua = "Mozilla/5.0 (compatible; Googlebot/2.1; " "+http://www.google.com/bot.html)"

    parsed = parser.parse(ua)
    assert parsed is not None
    assert parsed.device_type == "Bot"


def test_parse_empty_string():
    parser = UserAgentParser()
    assert parser.parse("") is None


def test_parse_garbage():
    parser = UserAgentParser()
    assert parser.parse("@@@ definitely-not-a-user-agent @@") is None


def test_vendor_lookup():
    parser = UserAgentParser()
    parsed = parser.parse(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    )

    assert parsed is not None
    if parsed.software_name == "Chrome":
        assert parsed.vendor == "Google"


def test_unknown_vendor():
    parser = UserAgentParser(vendor_map={"Firefox": "Mozilla"})
    parsed = parser.parse(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    )

    assert parsed is not None
    if parsed.software_name == "Chrome":
        assert parsed.vendor is None


def test_to_stix_software():
    parser = UserAgentParser()
    parsed = ParsedUserAgent(
        software_name="Chrome",
        software_version="125.0.0.0",
        os_name="Windows",
        os_version="10",
        device_type="PC",
        raw_string="Mozilla/5.0 ...",
        vendor="Google",
    )

    stix = parser.to_stix_software(parsed)
    assert stix["type"] == "Software"
    assert stix["name"] == "Chrome"
    assert stix["version"] == "125.0.0.0"
    assert stix["vendor"] == "Google"


def test_mobile_device_type():
    parser = UserAgentParser()
    ua = (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.0 Mobile/15E148 Safari/604.1"
    )

    parsed = parser.parse(ua)
    assert parsed is not None
    assert parsed.device_type in {"Mobile", "Tablet"}
