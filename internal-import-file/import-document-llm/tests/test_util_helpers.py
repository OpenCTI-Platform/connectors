"""Unit tests for reportimporter.util pure helpers and STIX factories."""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from reportimporter import util

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" + (
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
)


class TestStringHelpers:
    def test_patval_escapes(self):
        assert util._patval("o'brien") == "o\\'brien"
        assert util._patval("a\\b") == "a\\\\b"

    def test_normalize_path_collapses_double_backslash(self):
        assert util._normalize_path("C:\\\\Windows\\\\x") == "C:\\Windows\\x"
        assert util._normalize_path("") == ""

    def test_basename_mixed_separators(self):
        assert util._basename("C:\\path\\to\\file.txt") == "file.txt"
        assert util._basename("/a/b/c.py") == "c.py"

    def test_as_number_strips_prefix(self):
        assert util._as_number("AS123") == 123
        assert util._as_number("as456") == 456
        assert util._as_number("789") == 789


class TestNormalizeDomain:
    def test_valid_domain(self):
        assert util._normalize_domain("Example.com") == "example.com"

    def test_trailing_dot_is_stripped(self):
        assert util._normalize_domain("example.com.") == "example.com"

    def test_single_label_rejected(self):
        assert util._normalize_domain("localhost") is None

    def test_empty_rejected(self):
        assert util._normalize_domain("") is None

    def test_too_long_rejected(self):
        assert util._normalize_domain("a" * 250 + ".com") is None

    def test_empty_label_rejected(self):
        assert util._normalize_domain("a..b.com") is None

    def test_hyphenated_multilabel_domain(self):
        assert util._normalize_domain("my-host.co.uk") == "my-host.co.uk"

    def test_srv_label_rejects_non_hostname_punctuation(self):
        assert util._normalize_domain("svc:name.example.com") is None

    def test_raw_unicode_label_rejected(self):
        # Labels are validated against an ASCII-only pattern before IDNA.
        assert util._normalize_domain("münchen.de") is None


class TestSanitizeUrl:
    def test_strips_trailing_punctuation(self):
        assert util._sanitize_url("http://example.com/a.") == "http://example.com/a"

    def test_strips_surrounding_quotes(self):
        assert util._sanitize_url('"http://example.com"') == "http://example.com"

    def test_empty_returns_empty(self):
        assert util._sanitize_url("") == ""


class TestPhoneNumber:
    def test_valid_international(self):
        assert util._normalize_phone_number("+442083661177") == "+442083661177"

    def test_invalid_returns_none(self):
        assert util._normalize_phone_number("not-a-phone") is None

    def test_empty_returns_none(self):
        assert util._normalize_phone_number("") is None


class TestMakeStixId:
    def test_deterministic(self):
        a = util._make_stix_id("ipv4-addr", "1.2.3.4")
        b = util._make_stix_id("ipv4-addr", "1.2.3.4")
        assert a == b
        assert a.startswith("ipv4-addr--")


class TestRangeToCidrs:
    def test_basic_range(self):
        assert util.range_to_cidrs("223.166.0.0 - 223.167.255.255") == [
            "223.166.0.0/15"
        ]

    def test_unicode_dash(self):
        assert util.range_to_cidrs("1.0.0.0 \u2013 1.0.0.255") == ["1.0.0.0/24"]

    def test_empty(self):
        assert util.range_to_cidrs("") == []

    def test_no_dash(self):
        assert util.range_to_cidrs("1.2.3.4") == []

    def test_reversed_range(self):
        assert util.range_to_cidrs("10.0.0.5 - 10.0.0.1") == []

    def test_non_ipv4(self):
        assert util.range_to_cidrs("foo - bar") == []


class TestCountryCode:
    def test_alpha2(self):
        assert util._country_code("US") == "US"

    def test_alpha3(self):
        assert util._country_code("USA") == "US"

    def test_name(self):
        assert util._country_code("Belgium") == "BE"

    def test_empty(self):
        assert util._country_code("") == "XX"

    def test_unknown(self):
        assert util._country_code("Nowhereland") == "XX"

    def test_subdivision_falls_back(self):
        # A province/state is not a country -> XX
        assert util._country_code("California") == "XX"


class TestHashHelpers:
    @pytest.mark.parametrize(
        "value,algo,expected",
        [
            (MD5, "MD5", True),
            (SHA1, "SHA-1", True),
            (SHA256, "SHA-256", True),
            (SHA512, "SHA-512", True),
            ("deadbeef", "MD5", False),
            (MD5, "SHA-256", False),
            ("zz" + MD5[2:], "MD5", False),
        ],
    )
    def test_is_valid_hash(self, value, algo, expected):
        assert util._is_valid_hash(value, algo) is expected

    def test_create_file_hash_valid(self):
        f = util._create_file_hash(MD5, None, None, "MD5")
        assert f is not None
        assert f.hashes["MD5"] == MD5

    def test_create_file_hash_invalid(self):
        assert util._create_file_hash("bad", None, None, "MD5") is None


class TestCreateStixObject:
    def test_domain(self):
        out = util.create_stix_object("Domain-Name.value", "example.com", [], {})
        assert len(out) == 1
        assert out[0]["type"] == "domain-name"

    def test_ipv4(self):
        out = util.create_stix_object("IPv4-Addr.value", "1.2.3.4", [], {})
        assert out[0]["type"] == "ipv4-addr"

    def test_empty_value(self):
        assert util.create_stix_object("Domain-Name.value", "   ", [], {}) == []

    def test_unknown_category(self):
        assert util.create_stix_object("Not-A-Category", "x", [], {}) == []

    def test_malware_analysis_factory_is_dropped_gracefully(self):
        # A valid STIX 2.1 Malware Analysis needs result/analysis_sco_refs, which
        # the extractor does not provide, so the factory returns None and
        # create_stix_object maps that to [] (no exception, nothing emitted).
        assert util.create_stix_object("Malware-Analysis", "scan", [], {}) == []

    def test_invalid_domain_factory_returns_empty(self):
        # normalize keeps "localhost" but the factory's _normalize_domain
        # rejects it (single label) and returns None -> [].
        assert util.create_stix_object("Domain-Name.value", "localhost", [], {}) == []

    def test_phone_number_factory_flattens_custom_properties(self):
        marking_id = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
        created_by_ref = "identity--12345678-1234-1234-1234-123456789012"
        out = util.create_stix_object(
            "Phone-Number",
            "+442083661177",
            [marking_id],
            {"created_by_ref": created_by_ref, "x_original": "raw"},
        )

        assert len(out) == 1
        assert out[0]["id"] == util._make_stix_id("phone-number", "+442083661177")
        assert out[0]["object_marking_refs"] == [marking_id]
        assert out[0]["x_opencti_created_by_ref"] == created_by_ref
        assert out[0]["x_original"] == "raw"
        assert "custom_properties" not in out[0]


class TestComposeIndicators:
    def test_domain_indicator(self):
        inds = util.compose_indicators_from_observables(
            [{"type": "domain-name", "value": "example.com"}]
        )
        assert len(inds) == 1
        assert inds[0].pattern == "[domain-name:value = 'example.com']"

    def test_ipv4_url_email(self):
        obs = [
            {"type": "ipv4-addr", "value": "1.2.3.4"},
            {"type": "url", "value": "http://example.com/x"},
            {"type": "email-addr", "value": "User@Example.com"},
        ]
        inds = util.compose_indicators_from_observables(obs)
        patterns = {i.pattern for i in inds}
        assert "[ipv4-addr:value = '1.2.3.4']" in patterns
        assert any(p.startswith("[url:value =") for p in patterns)
        assert "[email-addr:value = 'user@example.com']" in patterns

    def test_file_hash_indicator(self):
        inds = util.compose_indicators_from_observables(
            [{"type": "file", "hashes": {"MD5": MD5}}]
        )
        assert len(inds) == 1
        assert "file:hashes.MD5" in inds[0].pattern

    def test_x509_serial_and_issuer(self):
        inds = util.compose_indicators_from_observables(
            [{"type": "x509-certificate", "serial_number": "ab:cd", "issuer": "CN=x"}]
        )
        assert len(inds) == 1
        assert "x509-certificate:serial_number" in inds[0].pattern

    def test_dedupes_by_pattern(self):
        obs = [
            {"type": "ipv4-addr", "value": "9.9.9.9"},
            {"type": "ipv4-addr", "value": "9.9.9.9"},
        ]
        assert len(util.compose_indicators_from_observables(obs)) == 1

    def test_existing_indicator_pattern_skipped(self):
        obs = [
            {"type": "indicator", "pattern": "[ipv4-addr:value = '8.8.8.8']"},
            {"type": "ipv4-addr", "value": "8.8.8.8"},
        ]
        assert util.compose_indicators_from_observables(obs) == []

    def test_compose_real_stix_object_serialize_branch(self):
        # stix2 .serialize() returns a JSON string (not a dict), so real stix2
        # objects are skipped by compose; callers pass already-serialized dicts.
        import stix2

        dn = stix2.DomainName(value="example.com")
        assert util.compose_indicators_from_observables([dn]) == []

    def test_compose_skips_non_dict_non_stix(self):
        assert util.compose_indicators_from_observables([12345, "x", None]) == []

    def test_compose_file_multiple_hashes(self):
        inds = util.compose_indicators_from_observables(
            [
                {
                    "type": "file",
                    "hashes": {"SHA-1": SHA1, "SHA-256": SHA256, "SHA-512": SHA512},
                }
            ]
        )
        assert len(inds) == 3

    def test_compose_x509_serial_only(self):
        inds = util.compose_indicators_from_observables(
            [{"type": "x509-certificate", "serial_number": "ab:cd"}]
        )
        assert len(inds) == 1
        assert "serial_number" in inds[0].pattern

    def test_compose_x509_issuer_only(self):
        inds = util.compose_indicators_from_observables(
            [{"type": "x509-certificate", "issuer": "CN=x"}]
        )
        assert len(inds) == 1
        assert "issuer" in inds[0].pattern


# (category, value, custom_properties) tuples exercising the factory mapping.
_FACTORY_CASES = [
    ("Artifact", "hello", {}),
    ("Autonomous-System.number", "AS123", {}),
    ("Directory", "C:\\temp", {}),
    ("Domain-Name.value", "example.com", {}),
    ("Email-Addr.value", "User@Example.com", {}),
    ("Email-Message.value", "Subject line", {}),
    ("File.hashes.MD5", MD5, {}),
    ("File.name", "evil.exe", {}),
    ("IPv4-Addr.value", "1.2.3.4", {}),
    ("IPv4-CIDR.value", "1.2.3.0/24", {}),
    ("IPv4-Range.value", "1.0.0.0 - 1.0.0.255", {}),
    ("IPv6-Addr.value", "::1", {}),
    ("Mac-Addr.value", "00:11:22:33:44:55", {}),
    ("Mutex", "global-mutex", {}),
    ("Phone-Number", "+442083661177", {}),
    ("Process", "cmd.exe", {}),
    ("Url.value", "http://example.com", {}),
    ("User-Account", "admin", {}),
    ("Windows-Registry-Key.key", "HKEY_LOCAL_MACHINE\\Run", {}),
    ("X509-Certificate.issuer", "CN=Test", {}),
    ("X509-Certificate.serial", "01:23:45", {}),
    ("X509-Certificate.sha1_fingerprint", SHA1, {}),
    ("X509-Certificate.sha256_fingerprint", SHA256, {}),
    ("X509-Certificate.subject", "CN=Subject", {}),
    ("Attack-Pattern.x_mitre_id", "T1059", {}),
    ("Campaign", "Operation X", {}),
    ("Channel", "telegram-channel", {}),
    ("City", "Paris, France", {}),
    ("Country", "Belgium", {}),
    ("Course-Of-Action", "Patch systems", {}),
    ("Identity", "ACME Corp", {}),
    ("Incident", "Breach 2026", {}),
    ("Individual", "John Doe", {}),
    ("Infrastructure", "C2 server", {}),
    ("Intrusion-Set", "APT1", {}),
    ("Malware", "Emotet", {}),
    ("Organization", "ACME Corp", {}),
    ("Region", "Europe", {}),
    ("Sector", "technology", {}),
    ("Software", "nginx", {}),
    ("Threat-Actor", "Some Actor", {}),
    ("Threat-Actor-Group", "Some Group", {}),
    ("Threat-Actor-Individual", "Some Person", {}),
    ("Tool", "Cobalt Strike", {}),
    ("Vulnerability.name", "CVE-2021-1234", {}),
]


@pytest.mark.parametrize("category,value,cp", _FACTORY_CASES)
def test_stix_object_mapping_factories(category, value, cp):
    factory = util.stix_object_mapping[category]
    obj = factory(value, [], cp)
    assert obj is not None
    if isinstance(obj, list):
        assert obj
        obj = obj[0]
    obj_type = obj["type"] if isinstance(obj, dict) else obj.type
    assert obj_type


def test_channel_factory_uses_object_marking_refs():
    marking_id = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    channel = util.stix_object_mapping["Channel"]("telegram-channel", [marking_id], {})

    assert channel.object_marking_refs == [marking_id]
    assert "object_markings" not in channel
