"""Tests for the IOC extractor module."""

import pytest
from crowdstrike_feeds_services.utils.ioc_extractor import (
    VALID_IOC_TYPES,
    ExtractedIOC,
    _is_valid_public_ip,
    extract_iocs,
)

ALL_TYPES = list(VALID_IOC_TYPES)

# ---------------------------------------------------------------------------
# _is_valid_public_ip
# ---------------------------------------------------------------------------


class TestIsValidPublicIp:
    """Tests for IP validation helper."""

    @pytest.mark.parametrize(
        "ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "45.33.32.156",
            "2607:f8b0:4004:800::200e",
        ],
    )
    def test_valid_public_ips(self, ip):
        assert _is_valid_public_ip(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "192.168.1.1",  # private
            "10.0.0.1",  # private
            "172.16.0.1",  # private
            "127.0.0.1",  # loopback
            "0.0.0.0",  # unspecified
            "255.255.255.255",  # broadcast/reserved
            "169.254.1.1",  # link-local
            "::1",  # ipv6 loopback
            "fe80::1",  # ipv6 link-local
            "2001:db8::1",  # ipv6 documentation
            "not-an-ip",
            "",
        ],
    )
    def test_rejects_non_public_ips(self, ip):
        assert _is_valid_public_ip(ip) is False


# ---------------------------------------------------------------------------
# extract_iocs
# ---------------------------------------------------------------------------


class TestExtractIocs:
    """Tests for the main extract_iocs function."""

    def test_empty_text_returns_empty(self):
        assert extract_iocs("", ALL_TYPES) == []

    def test_empty_types_returns_empty(self):
        assert extract_iocs("IP: 8.8.8.8", []) == []

    def test_no_iocs_returns_empty(self):
        assert (
            extract_iocs("This text has no indicators of compromise.", ALL_TYPES) == []
        )

    def test_extracts_public_ipv4(self):
        result = extract_iocs(
            "Observed connections to 45.33.32.156 from host.", ALL_TYPES
        )
        assert ExtractedIOC("ipv4", "45.33.32.156") in result

    def test_ignores_private_ipv4(self):
        result = extract_iocs("Internal host 192.168.1.1 and 10.0.0.1", ALL_TYPES)
        ipv4s = [r for r in result if r.type == "ipv4"]
        assert len(ipv4s) == 0

    def test_extracts_domain(self):
        result = extract_iocs("C2 callback to evil-c2.example.com observed.", ALL_TYPES)
        assert ExtractedIOC("domain", "evil-c2.example.com") in result

    def test_extracts_url(self):
        result = extract_iocs(
            "Downloaded from https://malware.example.org/payload", ALL_TYPES
        )
        urls = [r for r in result if r.type == "url"]
        assert len(urls) == 1
        assert urls[0].value == "https://malware.example.org/payload"

    def test_extracts_md5(self):
        result = extract_iocs("MD5: d41d8cd98f00b204e9800998ecf8427e", ALL_TYPES)
        assert ExtractedIOC("md5", "d41d8cd98f00b204e9800998ecf8427e") in result

    def test_extracts_sha1(self):
        result = extract_iocs(
            "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709", ALL_TYPES
        )
        assert (
            ExtractedIOC("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709") in result
        )

    def test_extracts_sha256(self):
        hash_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = extract_iocs(f"SHA256: {hash_val}", ALL_TYPES)
        assert ExtractedIOC("sha256", hash_val) in result

    def test_sha256_not_matched_as_shorter_hashes(self):
        """A SHA-256 should not also produce spurious MD5 or SHA-1 matches."""
        hash_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = extract_iocs(f"Hash: {hash_val}", ALL_TYPES)
        types = {r.type for r in result}
        assert "sha256" in types
        assert "md5" not in types
        assert "sha1" not in types

    def test_deduplicates_same_ioc(self):
        result = extract_iocs("IP 8.8.8.8 and again 8.8.8.8", ALL_TYPES)
        ipv4_results = [r for r in result if r.value == "8.8.8.8"]
        assert len(ipv4_results) == 1

    def test_defanged_domain(self):
        result = extract_iocs("C2: evil[.]example[.]com", ALL_TYPES)
        assert ExtractedIOC("domain", "evil.example.com") in result

    def test_defanged_url(self):
        result = extract_iocs("URL: hxxps://evil[.]org/malware", ALL_TYPES)
        urls = [r for r in result if r.type == "url"]
        assert len(urls) == 1
        assert urls[0].value == "https://evil.org/malware"

    def test_domain_inside_url_not_duplicated(self):
        """When a URL is extracted, its domain should not appear separately."""
        result = extract_iocs("Visit https://evil.example.com/path", ALL_TYPES)
        types = [r.type for r in result]
        assert "url" in types
        assert "domain" not in types

    def test_mixed_iocs(self):
        """Extract multiple IOC types from a single text block."""
        text = (
            "The actor used 45.33.32.156 as C2. "
            "Domain evil.example.com resolved to that IP. "
            "Payload hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        result = extract_iocs(text, ALL_TYPES)
        types = {r.type for r in result}
        assert {"ipv4", "domain", "sha256"}.issubset(types)

    def test_selective_types_only_extracts_requested(self):
        """Only requested IOC types should be returned."""
        text = "IP 8.8.8.8 domain evil.com hash d41d8cd98f00b204e9800998ecf8427e"
        result = extract_iocs(text, ["ipv4"])
        types = {r.type for r in result}
        assert types == {"ipv4"}

    def test_domain_extracted_alone_without_url_dedup(self):
        """When only domain is requested (not url), standalone domains are still extracted."""
        result = extract_iocs("Domain evil.example.com observed", ["domain"])
        assert len(result) == 1
        assert result[0].type == "domain"
