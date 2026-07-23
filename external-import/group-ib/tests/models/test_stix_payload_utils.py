from __future__ import annotations

from unittest.mock import patch

import pytest
from models._common import BaseEntity, StixPayloadUtils

# --- _sanitize ----------------------------------------------------------------


class TestSanitize:
    def test_empty_string_returns_empty(self):
        assert StixPayloadUtils._sanitize("") == ""

    def test_none_returns_empty(self):
        assert StixPayloadUtils._sanitize(None) == ""

    def test_plain_string_unchanged(self):
        assert StixPayloadUtils._sanitize("hello world") == "hello world"

    def test_strips_null_bytes_and_low_ctl(self):
        # CTRL_CHAR_RE strips \x00-\x08, \x0b, \x0c, \x0e-\x1f.
        assert StixPayloadUtils._sanitize("a\x00b\x07c") == "abc"

    def test_keeps_newline_tab_carriage_return(self):
        # \n (0x0a), \r (0x0d), \t (0x09) are valid markdown whitespace
        # and must survive sanitisation.
        assert StixPayloadUtils._sanitize("a\nb\tc\rd") == "a\nb\tc\rd"

    def test_coerces_non_string(self):
        # The implementation runs ``str(message)`` before the regex sub.
        assert StixPayloadUtils._sanitize(42) == "42"


# --- _remove_html_tags --------------------------------------------------------


class TestRemoveHtmlTags:
    def test_strips_simple_tag(self):
        assert StixPayloadUtils._remove_html_tags("<b>x</b>") == "x"

    def test_strips_anchor_with_attrs(self):
        out = StixPayloadUtils._remove_html_tags(
            '<a href="http://example.com">link</a>'
        )
        assert out == "link"

    def test_strips_self_closing(self):
        assert StixPayloadUtils._remove_html_tags("a<br/>b") == "ab"

    def test_no_tags_unchanged(self):
        assert StixPayloadUtils._remove_html_tags("plain text") == "plain text"

    def test_empty_string(self):
        assert StixPayloadUtils._remove_html_tags("") == ""


# --- _extract_domain ----------------------------------------------------------


class TestExtractDomain:
    def test_empty_returns_empty(self):
        assert StixPayloadUtils._extract_domain("") == ""

    def test_none_returns_empty(self):
        assert StixPayloadUtils._extract_domain(None) == ""

    def test_simple_url(self):
        assert StixPayloadUtils._extract_domain("https://example.com") == "example.com"

    def test_url_with_trailing_slash(self):
        # Trailing "/" alone is treated as "no path" — no suffix appended.
        assert StixPayloadUtils._extract_domain("https://example.com/") == "example.com"

    def test_url_with_path_appends_suffix(self):
        # When the URL has a real path (anything beyond "/"), the suffix
        # parameter is appended to the netloc so the caller can mark the
        # ref-id (e.g. ``"#path-present"``) if it wants.
        out = StixPayloadUtils._extract_domain(
            "https://example.com/some/page", suffix="#tag"
        )
        assert out == "example.com#tag"

    def test_url_with_port(self):
        # urlparse keeps host:port together in netloc.
        out = StixPayloadUtils._extract_domain("http://example.com:8080/x")
        assert out.startswith("example.com:8080")

    def test_obfuscated_host_with_brackets_falls_through(self):
        # ``urlparse`` chokes on ``example.web[.]app`` — the function
        # catches the ValueError and uses a manual split.
        out = StixPayloadUtils._extract_domain("http://example.web[.]app/path")
        assert "example.web[.]app" in out

    def test_list_input_returns_empty(self):
        # Regression guard for OpenCTI-connectors/issues/6341: upstream
        # payloads occasionally deliver ``portal_link`` as a list; the
        # function must not reach ``urlparse`` in that case.
        assert StixPayloadUtils._extract_domain(["https://example.com"]) == ""
        assert StixPayloadUtils._extract_domain([]) == ""


# --- IP validation ------------------------------------------------------------


class TestIsIpv4:
    def test_valid_ipv4(self):
        assert StixPayloadUtils.is_ipv4("192.0.2.1") is True
        assert StixPayloadUtils.is_ipv4("192.168.0.1") is True
        assert StixPayloadUtils.is_ipv4("255.255.255.255") is True
        assert StixPayloadUtils.is_ipv4("0.0.0.0") is True

    def test_invalid_ipv4_format(self):
        assert StixPayloadUtils.is_ipv4("1.2.3") is False
        assert StixPayloadUtils.is_ipv4("192.0.2.1.5") is False
        assert StixPayloadUtils.is_ipv4("256.1.1.1") is False
        assert StixPayloadUtils.is_ipv4("not-an-ip") is False
        assert StixPayloadUtils.is_ipv4("") is False

    def test_ipv6_is_not_ipv4(self):
        assert StixPayloadUtils.is_ipv4("::1") is False
        assert StixPayloadUtils.is_ipv4("2001:db8::1") is False


class TestIsIpv6:
    def test_valid_ipv6(self):
        assert StixPayloadUtils.is_ipv6("::1") is True
        assert StixPayloadUtils.is_ipv6("2001:db8::1") is True
        assert StixPayloadUtils.is_ipv6("fe80::1ff:fe23:4567:890a") is True

    def test_invalid_ipv6(self):
        assert StixPayloadUtils.is_ipv6("not-an-ip") is False
        assert StixPayloadUtils.is_ipv6("") is False
        assert StixPayloadUtils.is_ipv6("2001:db8::1::1") is False  # double-collapse

    def test_ipv4_is_not_ipv6(self):
        assert StixPayloadUtils.is_ipv6("192.0.2.1") is False


# --- determine_hash_algorithm_by_length --------------------------------------


class TestHashAlgorithmByLength:
    def test_md5(self):
        h = "d41d8cd98f00b204e9800998ecf8427e"  # md5("")
        assert StixPayloadUtils.determine_hash_algorithm_by_length(h) == "MD5"

    def test_sha1(self):
        h = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # sha1("")
        assert StixPayloadUtils.determine_hash_algorithm_by_length(h) == "SHA-1"

    def test_sha256(self):
        h = (
            "e3b0c44298fc1c149afbf4c8996fb924" "27ae41e4649b934ca495991b7852b855"
        )  # sha256("")
        assert StixPayloadUtils.determine_hash_algorithm_by_length(h) == "SHA-256"

    def test_invalid_length_raises(self):
        with pytest.raises(ValueError):
            StixPayloadUtils.determine_hash_algorithm_by_length("tooshort")

    def test_invalid_length_message_includes_hash(self):
        with pytest.raises(ValueError, match="abc123"):
            StixPayloadUtils.determine_hash_algorithm_by_length("abc123")


# --- stix_escape (lives on BaseEntity but is pure-static logic) ---------------


class TestStixEscape:
    def test_escapes_single_quote(self):
        assert BaseEntity.stix_escape("a'b") == "a\\'b"

    def test_escapes_backslash(self):
        # One literal backslash → escaped to two backslashes.
        assert BaseEntity.stix_escape("a\\b") == "a\\\\b"

    def test_escapes_both(self):
        # Order matters: backslash escape runs first, then quote escape.
        assert BaseEntity.stix_escape("a'b\\c") == "a\\'b\\\\c"

    def test_no_special_chars(self):
        assert BaseEntity.stix_escape("plain") == "plain"

    def test_empty_string(self):
        assert BaseEntity.stix_escape("") == ""


# --- ConfigConnector lookup helpers ------------------------------------------


class TestGenerateTlpObj:
    def test_known_lowercase(self):
        out = StixPayloadUtils._generate_tlp_obj("amber")
        assert out is not None

    def test_known_uppercase_normalised(self):
        # Implementation lowercases the input before lookup.
        out = StixPayloadUtils._generate_tlp_obj("RED")
        assert out is not None

    def test_amber_strict_via_plus(self):
        # The map key uses "amber+strict" (lowercase, with the plus).
        out = StixPayloadUtils._generate_tlp_obj("amber+strict")
        assert out is not None

    def test_empty_falls_back_to_white(self):
        white = StixPayloadUtils._generate_tlp_obj("white")
        out = StixPayloadUtils._generate_tlp_obj("")
        assert out is white

    def test_none_falls_back_to_white(self):
        white = StixPayloadUtils._generate_tlp_obj("white")
        out = StixPayloadUtils._generate_tlp_obj(None)
        assert out is white

    def test_unknown_falls_back_to_white(self):
        # Unknown colour silently maps to TLP:WHITE.
        white = StixPayloadUtils._generate_tlp_obj("white")
        out = StixPayloadUtils._generate_tlp_obj("not-a-tlp")
        assert out is white


class TestGenerateMainObservableType:
    def test_known_alias(self):
        assert (
            StixPayloadUtils._generate_main_observable_type("domain") == "Domain-Name"
        )

    def test_known_canonical(self):
        assert (
            StixPayloadUtils._generate_main_observable_type("ipv4-addr") == "IPv4-Addr"
        )

    def test_file_maps_to_stixfile(self):
        assert StixPayloadUtils._generate_main_observable_type("file") == "StixFile"

    def test_yara_maps_to_stixfile(self):
        # YARA indicators ultimately live on a file SCO in OpenCTI.
        assert StixPayloadUtils._generate_main_observable_type("yara") == "StixFile"

    def test_unknown_returns_none(self):
        assert StixPayloadUtils._generate_main_observable_type("never") is None


class TestGenerateMalwareType:
    def test_known_lowercase(self):
        # Real STIX 2.1 ``malware-type-ov`` entries include "ransomware".
        out = StixPayloadUtils._generate_malware_type("ransomware")
        assert out == "ransomware"

    def test_known_uppercase_lowercased(self):
        out = StixPayloadUtils._generate_malware_type("RANSOMWARE")
        assert out == "ransomware"

    def test_unknown_returns_none(self):
        assert StixPayloadUtils._generate_malware_type("not-a-family") is None


class TestGenerateCountryByCc:
    def test_known_code(self):
        assert StixPayloadUtils._generate_country_by_cc("US") == "United States"

    def test_unknown_returns_none(self):
        assert StixPayloadUtils._generate_country_by_cc("XX") is None


class TestGenerateStixReportType:
    def test_threat_report(self):
        assert (
            StixPayloadUtils._generate_stix_report_type("threat_report")
            == "Threat-Report"
        )

    def test_unknown_returns_none(self):
        assert StixPayloadUtils._generate_stix_report_type("never") is None


class TestExtractDomainValueErrorFallback:
    def test_urlparse_value_error_path(self):
        # ``urlparse`` rarely raises ValueError, but the wrapper guards
        # against it by manually splitting on ``://`` and ``/``. Force
        # the raise via a patched urlparse and verify the fallback runs.
        with patch(
            "models._common.urlparse",
            side_effect=ValueError("malformed url"),
        ):
            out = StixPayloadUtils._extract_domain(
                "http://host.example.com/path",
                suffix="!",
            )
        # Fallback manually extracts the host and appends the suffix.
        assert "host.example.com" in out
        assert out.endswith("!")


class TestExtractDomainObfuscated:
    def test_url_with_obfuscated_brackets(self):
        # ``urlparse`` normally tolerates "example.web[.]app", so this
        # only confirms the fallback path doesn't crash — the actual
        # ValueError trigger is implementation-specific.
        out = StixPayloadUtils._extract_domain("http://x[.]y/path", suffix="!")
        assert isinstance(out, str) and len(out) > 0
