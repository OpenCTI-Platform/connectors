from connector.extractor import (
    extract_iocs,
    is_public_ip,
)


class TestIsPublicIpv4:
    def test_public_ip(self):
        assert is_public_ip("8.8.8.8") is True

    def test_private_ip(self):
        assert is_public_ip("192.168.1.1") is False
        assert is_public_ip("10.0.0.1") is False
        assert is_public_ip("172.16.0.1") is False

    def test_loopback(self):
        assert is_public_ip("127.0.0.1") is False

    def test_invalid(self):
        assert is_public_ip("not_an_ip") is False


class TestExtractIocs:
    def test_extract_ipv4(self):
        text = "The attacker used 8.8.8.8 to exfiltrate data"
        iocs = extract_iocs(text, extract_ipv4=True)
        assert any(ioc.type == "ipv4" and ioc.value == "8.8.8.8" for ioc in iocs)

    def test_exclude_private_ipv4(self):
        text = "Internal server at 192.168.1.1 was compromised"
        iocs = extract_iocs(text, extract_ipv4=True)
        assert not any(ioc.value == "192.168.1.1" for ioc in iocs)

    def test_include_private_ipv4_when_skip_disabled(self):
        text = "Internal server at 192.168.1.1 was compromised"
        iocs = extract_iocs(text, extract_ipv4=True, skip_private_ips=False)
        assert any(ioc.value == "192.168.1.1" for ioc in iocs)

    def test_extract_domain(self):
        text = "Malware connects to evil.example.com for C2"
        iocs = extract_iocs(text, extract_domains=True)
        assert any(ioc.type == "domain" and "example.com" in ioc.value for ioc in iocs)

    def test_extract_url(self):
        text = "Downloaded payload from https://malware.example.com/payload.exe"
        iocs = extract_iocs(text, extract_urls=True)
        assert any(ioc.type == "url" for ioc in iocs)

    def test_extract_md5(self):
        text = "File hash: d41d8cd98f00b204e9800998ecf8427e"
        iocs = extract_iocs(text, extract_hashes=True)
        assert any(
            ioc.type == "md5" and ioc.value == "d41d8cd98f00b204e9800998ecf8427e"
            for ioc in iocs
        )

    def test_extract_sha256(self):
        text = (
            "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        iocs = extract_iocs(text, extract_hashes=True)
        assert any(ioc.type == "sha256" for ioc in iocs)

    def test_extract_sha1(self):
        text = "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709"
        iocs = extract_iocs(text, extract_hashes=True)
        assert any(ioc.type == "sha1" for ioc in iocs)

    def test_disabled_type_not_extracted(self):
        text = "IP: 8.8.8.8, domain: evil.com"
        iocs = extract_iocs(text, extract_ipv4=False, extract_domains=True)
        assert not any(ioc.type == "ipv4" for ioc in iocs)

    def test_empty_text(self):
        assert extract_iocs("") == []
        assert extract_iocs("   ") == []

    def test_no_iocs(self):
        text = "This is a normal sentence with no indicators"
        iocs = extract_iocs(text)
        assert len(iocs) == 0


class TestExtractIocsFromDescription:
    def test_description_parsed(self):
        iocs = extract_iocs("Attacker IP: 8.8.8.8")
        assert any(ioc.value == "8.8.8.8" for ioc in iocs)

    def test_no_content(self):
        assert extract_iocs("") == []
        assert extract_iocs("   ") == []
