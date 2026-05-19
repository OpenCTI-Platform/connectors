"""Unit tests pinning the malware-config / indicator-creation additions.

These tests exercise the *pure* helpers added on top of the master
``LivehuntBuilder`` so we can pin their contract without standing up
the full builder (which needs a live VirusTotal client + OpenCTI
helper). The helpers covered here are:

* :func:`livehunt.builder._escape_stix_pattern_value`
* :func:`LivehuntBuilder._is_valid_domain_name`
* :func:`LivehuntBuilder._ip_version`
* :func:`LivehuntBuilder._unique_strings`
"""

import pytest
from livehunt.builder import LivehuntBuilder, _escape_stix_pattern_value


class TestEscapeStixPatternValue:
    """STIX pattern values must escape backslashes and single quotes.

    Without this, IOCs containing either character produce a malformed
    pattern AND a mismatched deterministic indicator id, which silently
    drops the indicator on import.
    """

    def test_escape_single_quote(self):
        assert _escape_stix_pattern_value("a'b") == "a\\'b"

    def test_escape_backslash(self):
        assert _escape_stix_pattern_value("a\\b") == "a\\\\b"

    def test_escape_quote_and_backslash(self):
        assert _escape_stix_pattern_value("a\\b'c") == "a\\\\b\\'c"

    def test_no_escape_when_clean(self):
        assert _escape_stix_pattern_value("evil.example.com") == "evil.example.com"


class TestIsValidDomainName:
    """Domain validation must be regex-only — no live DNS resolution.

    Live DNS queries (e.g. via ``dns.google``) drop valid C2 domains
    that are NXDOMAIN, blocked by network policy, or AAAA-only, and
    add per-host latency to processing.
    """

    @pytest.mark.parametrize(
        "domain",
        [
            "evil.example.com",
            "a.b.example.org",
            "xn--bcher-kva.example",  # IDN-encoded
            "1.example.com",
        ],
    )
    def test_valid_domains(self, domain: str) -> None:
        assert LivehuntBuilder._is_valid_domain_name(domain) is True

    @pytest.mark.parametrize(
        "domain",
        [
            "",
            "noTLD",
            "-leading-dash.example.com",
            "example.com/path",
            "evil.example.com.",
            "http://evil.example.com",
            "evil. example.com",
        ],
    )
    def test_invalid_domains(self, domain: str) -> None:
        assert LivehuntBuilder._is_valid_domain_name(domain) is False


class TestIpVersion:
    """``_ip_version`` returns 4 / 6 for valid addresses, None otherwise."""

    @pytest.mark.parametrize(
        "address, version",
        [
            ("1.2.3.4", 4),
            ("10.0.0.1", 4),
            ("::1", 6),
            ("2001:db8::1", 6),
            ("fe80::1", 6),
        ],
    )
    def test_valid(self, address: str, version: int) -> None:
        assert LivehuntBuilder._ip_version(address) == version

    @pytest.mark.parametrize(
        "address",
        [
            "",
            "not-an-ip",
            "256.0.0.1",
            "1.2.3",
            ":::::::",
        ],
    )
    def test_invalid(self, address: str) -> None:
        assert LivehuntBuilder._ip_version(address) is None


class TestUniqueStrings:
    """Deduplicate, strip, drop empties and non-strings."""

    def test_dedup_preserves_order(self) -> None:
        assert LivehuntBuilder._unique_strings(["a", "b", "a", "c", "b"]) == [
            "a",
            "b",
            "c",
        ]

    def test_strips_whitespace_and_drops_empty(self) -> None:
        assert LivehuntBuilder._unique_strings(["  a  ", "", "   ", "b"]) == ["a", "b"]

    def test_drops_non_strings(self) -> None:
        assert LivehuntBuilder._unique_strings(["a", 1, None, "b", b"c"]) == ["a", "b"]

    def test_none_and_empty_input(self) -> None:
        assert LivehuntBuilder._unique_strings(None) == []
        assert LivehuntBuilder._unique_strings([]) == []
