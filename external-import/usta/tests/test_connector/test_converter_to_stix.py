"""Unit tests for the USTA STIX converter — 100 % branch coverage."""

# pylint: disable=missing-function-docstring,missing-class-docstring,too-many-lines
# pylint: disable=protected-access,import-outside-toplevel,unused-argument

from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import ConverterToStix

# =====================================================================
# Initialization
# =====================================================================


class TestInit:
    def test_author_identity(self, mock_helper):
        c = ConverterToStix(mock_helper)
        assert c.author.name == "USTA"
        assert c.author.identity_class == "organization"

    def test_default_tlp(self, mock_helper):
        c = ConverterToStix(mock_helper)
        assert "marking-definition" in c.tlp_marking.id

    def test_each_tlp_level(self, mock_helper):
        for level in ("clear", "white", "green", "amber", "red"):
            c = ConverterToStix(mock_helper, tlp_level=level)
            assert c.tlp_marking is not None

    def test_unknown_tlp_falls_back_to_amber(self, mock_helper):
        c = ConverterToStix(mock_helper, tlp_level="NONEXISTENT")
        assert c.tlp_marking == ConverterToStix.TLP_MARKING_MAP["amber"]

    def test_deterministic_author_id(self, mock_helper):
        assert (
            ConverterToStix(mock_helper, author_name="A").author.id
            == ConverterToStix(mock_helper, author_name="A").author.id
        )


# =====================================================================
# Static / internal helpers
# =====================================================================


class TestParseDatetime:
    def test_none_returns_now(self, mock_helper):
        result = ConverterToStix._parse_datetime(None)
        assert result.endswith("Z")

    def test_plus_utc_suffix_replaced(self, mock_helper):
        assert (
            ConverterToStix._parse_datetime("2026-01-01T00:00:00+00:00")
            == "2026-01-01T00:00:00Z"
        )

    def test_normal_passthrough(self, mock_helper):
        assert (
            ConverterToStix._parse_datetime("2026-01-01T00:00:00Z")
            == "2026-01-01T00:00:00Z"
        )


class TestExtractHost:
    def test_with_scheme(self):
        assert ConverterToStix._extract_host("https://evil.com:443/path") == "evil.com"

    def test_without_scheme(self):
        assert ConverterToStix._extract_host("evil.com:443") == "evil.com"

    def test_ip_with_port(self):
        assert ConverterToStix._extract_host("1.2.3.4:8080") == "1.2.3.4"

    def test_bare_domain(self):
        assert ConverterToStix._extract_host("example.org") == "example.org"

    def test_no_match_with_colon(self):
        # Contrived input where regex cannot match but colon exists
        assert ConverterToStix._extract_host(":something") == ""


class TestIsIp:
    def test_valid_ipv4(self):
        assert ConverterToStix._is_ip("1.2.3.4") is True

    def test_valid_ipv6(self):
        assert ConverterToStix._is_ip("::1") is True

    def test_invalid(self):
        assert ConverterToStix._is_ip("not-an-ip") is False


class TestIsIpv6:
    def test_ipv6(self):
        assert ConverterToStix._is_ipv6("2001:db8::1") is True

    def test_ipv4(self):
        assert ConverterToStix._is_ipv6("1.2.3.4") is False

    def test_invalid(self):
        assert ConverterToStix._is_ipv6("garbage") is False


class TestMainObservableType:
    def test_domain(self):
        assert (
            ConverterToStix._main_observable_type(True, "evil.com", []) == "Domain-Name"
        )

    def test_ip_addresses(self):
        assert (
            ConverterToStix._main_observable_type(False, "", ["1.2.3.4"]) == "IPv4-Addr"
        )

    def test_host_ipv4(self):
        assert (
            ConverterToStix._main_observable_type(False, "1.2.3.4", []) == "IPv4-Addr"
        )

    def test_host_ipv6(self):
        assert ConverterToStix._main_observable_type(False, "::1", []) == "IPv6-Addr"

    def test_host_domain_fallback(self):
        assert (
            ConverterToStix._main_observable_type(False, "evil.com", [])
            == "Domain-Name"
        )

    def test_nothing(self):
        assert ConverterToStix._main_observable_type(False, "", []) == "Url"


class TestMaskCardNumber:
    def test_standard_16(self):
        assert (
            ConverterToStix._mask_card_number("4289691967078106") == "428969******8106"
        )

    def test_short_card(self):
        assert ConverterToStix._mask_card_number("12345") == "*****"

    def test_with_spaces_and_dashes(self):
        assert (
            ConverterToStix._mask_card_number("4289-6919-6707-8106")
            == "428969******8106"
        )


# =====================================================================
# Observable helpers
# =====================================================================


class TestObservableHelpers:
    def test_ipv4(self, mock_helper):
        c = ConverterToStix(mock_helper)
        obs = c._create_ipv4_observable("1.2.3.4")
        assert obs.type == "ipv4-addr"
        assert obs.value == "1.2.3.4"

    def test_ipv6(self, mock_helper):
        c = ConverterToStix(mock_helper)
        obs = c._create_ipv6_observable("2001:db8::1")
        assert obs.type == "ipv6-addr"

    def test_domain(self, mock_helper):
        c = ConverterToStix(mock_helper)
        obs = c._create_domain_observable("evil.com")
        assert obs.type == "domain-name"

    def test_url(self, mock_helper):
        c = ConverterToStix(mock_helper)
        obs = c._create_url_observable("https://evil.com")
        assert obs.type == "url"

    def test_file_all_hashes(self, mock_helper):
        c = ConverterToStix(mock_helper)
        obs = c._create_file_observable(
            md5="bf92342b0a0c34878bb3ef89b9f18196",
            sha1="5b960c29570ea3d8af2a7dde7ddf6672d6a9a024",
            sha256="285f7b8f2bbee896cf8a14af480f1f09811bdcd6cd2abff12a0046a0d286f131",
        )
        assert obs.type == "file"
        assert "MD5" in obs.hashes

    def test_file_only_md5(self, mock_helper):
        c = ConverterToStix(mock_helper)
        obs = c._create_file_observable(md5="bf92342b0a0c34878bb3ef89b9f18196")
        assert "MD5" in obs.hashes

    def test_file_no_hashes_raises(self, mock_helper):
        c = ConverterToStix(mock_helper)
        with pytest.raises(ValueError):
            c._create_file_observable()

    def test_user_account_deterministic(self, mock_helper):
        c = ConverterToStix(mock_helper)
        a1 = c._create_user_account_observable("user@test.com", "s3cr3t", record_id=42)
        a2 = c._create_user_account_observable("user@test.com", "s3cr3t", record_id=42)
        assert a1.id == a2.id
        assert a1.account_login == "user@test.com"

    def test_user_account_same_record_id_gives_same_id_regardless_of_password(
        self, mock_helper
    ):
        # Password no longer influences the deterministic ID — only record_id does.
        c = ConverterToStix(mock_helper)
        a1 = c._create_user_account_observable("user@test.com", "pass1", record_id=99)
        a2 = c._create_user_account_observable("user@test.com", "pass2", record_id=99)
        assert a1.id == a2.id

    def test_user_account_different_record_id_gives_different_id(self, mock_helper):
        c = ConverterToStix(mock_helper)
        a1 = c._create_user_account_observable("user@test.com", "pass", record_id=1)
        a2 = c._create_user_account_observable("user@test.com", "pass", record_id=2)
        assert a1.id != a2.id

    def test_user_account_labels_stored_in_custom_property(self, mock_helper):
        c = ConverterToStix(mock_helper)
        ua = c._create_user_account_observable(
            "u@t.com",
            "p",
            labels=["corporate", "malware"],
        )
        assert ua.get("x_opencti_labels") == ["corporate", "malware"]

    def test_user_account_no_labels_omits_custom_property(self, mock_helper):
        c = ConverterToStix(mock_helper)
        ua = c._create_user_account_observable("u", "p")
        assert ua.get("x_opencti_labels") is None


# =====================================================================
# Malicious URL conversion — all branches
# =====================================================================


class TestConvertMaliciousUrl:
    def test_ip_based(self, mock_helper, sample_malicious_url_record):
        c = ConverterToStix(mock_helper)
        result = c.convert_malicious_url(sample_malicious_url_record)
        types = {o.type for o in result}
        assert {"ipv4-addr", "url", "indicator", "malware", "relationship"} <= types

    def test_empty_url(self, mock_helper):
        assert not ConverterToStix(mock_helper).convert_malicious_url({"url": ""})

    def test_domain_based(self, mock_helper):
        record = {
            "url": "evil.com:443",
            "host": "evil.com",
            "is_domain": True,
            "ip_addresses": [],
            "tags": [],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
        }
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        types = {o.type for o in result}
        assert "domain-name" in types

    def test_ipv6_in_ip_addresses(self, mock_helper):
        record = {
            "url": "[::1]:80",
            "host": "::1",
            "is_domain": False,
            "ip_addresses": ["2001:db8::1"],
            "tags": [],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
        }
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        types = {o.type for o in result}
        assert "ipv6-addr" in types

    def test_host_only_ip_fallback(self, mock_helper):
        """No ip_addresses, not domain, host is an IP → uses host."""
        record = {
            "url": "10.0.0.1:80",
            "host": "10.0.0.1",
            "is_domain": False,
            "ip_addresses": [],
            "tags": [],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
        }
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        types = {o.type for o in result}
        assert "ipv4-addr" in types

    def test_host_only_domain_fallback(self, mock_helper):
        """No ip_addresses, not is_domain flag, host is a domain string."""
        record = {
            "url": "bad.org",
            "host": "bad.org",
            "is_domain": True,
            "ip_addresses": [],
            "tags": [],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
        }
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        types = {o.type for o in result}
        assert "domain-name" in types

    def test_host_not_ip(self, mock_helper):
        """No ip_addresses, not is_domain flag, host is filled."""
        record = {
            "url": "http://example.com",
            "host": "example.com",
            "is_domain": False,
            "ip_addresses": [],
            "tags": [],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
        }
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        types = {o.type for o in result}
        assert "domain-name" in types

    def test_convert_malicious_url_path_only_skipped(self, mock_helper):
        """Path-only URLs (no host, no scheme) must not produce an indicator."""
        converter = ConverterToStix(mock_helper)

        record = {
            "url": "/api/v1/malware",
            "host": "",
            "is_domain": False,
            "ip_addresses": [],
            "tags": ["test"],
            "valid_from": "2026-01-01T00:00:00Z",
        }

        result = converter.convert_malicious_url(record)

        assert not any(o["type"] == "indicator" for o in result)

    def test_convert_malicious_url_fallback_with_scheme(self, mock_helper):
        converter = ConverterToStix(mock_helper)
        converter._extract_host = MagicMock(return_value="")
        converter._is_ip = MagicMock(return_value=False)

        record = {
            "url": "https://unknown-format-url.com",
            "host": "",
            "is_domain": False,
            "ip_addresses": [],
            "valid_from": "2026-01-01T00:00:00Z",
        }

        result = converter.convert_malicious_url(record)

        indicator = next(o for o in result if o["type"] == "indicator")
        assert "url:value = 'https://unknown-format-url.com'" in indicator["pattern"]

    def test_multiple_ips_or_pattern(self, mock_helper):
        """Two IPs → OR-joined pattern."""
        record = {
            "url": "1.1.1.1:80",
            "host": "",
            "is_domain": False,
            "ip_addresses": ["1.1.1.1", "2.2.2.2"],
            "tags": [],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
        }
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        indicators = [o for o in result if o.type == "indicator"]
        assert " OR " in indicators[0].pattern

    def test_invalid_ip_in_list_skipped(self, mock_helper):
        record = {
            "url": "x:80",
            "host": "",
            "is_domain": True,
            "ip_addresses": ["not-an-ip"],
            "tags": [],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
        }
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        # No observable created for invalid IP, falls back to URL pattern
        indicators = [o for o in result if o.type == "indicator"]
        assert len(indicators) == 1

    def test_url_without_slash_or_colon_no_extra_url_obs(self, mock_helper):
        record = {
            "url": "plaintext",
            "host": "",
            "is_domain": True,
            "ip_addresses": [],
            "tags": [],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
        }
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        url_obs = [o for o in result if o.type == "url"]
        assert len(url_obs) == 0

    def test_tags_produce_malware_and_relationship(
        self, mock_helper, sample_malicious_url_record
    ):
        result = ConverterToStix(mock_helper).convert_malicious_url(
            sample_malicious_url_record
        )
        assert any(o.type == "malware" and o.name == "Ghost RAT" for o in result)
        rel_types = {o.relationship_type for o in result if o.type == "relationship"}
        assert "indicates" in rel_types
        assert "based-on" in rel_types

    def test_deterministic_ids(self, mock_helper, sample_malicious_url_record):
        c = ConverterToStix(mock_helper)
        assert {o.id for o in c.convert_malicious_url(sample_malicious_url_record)} == {
            o.id for o in c.convert_malicious_url(sample_malicious_url_record)
        }


# =====================================================================
# Phishing Site conversion
# =====================================================================


class TestConvertPhishingSite:
    def test_basic(self, mock_helper, sample_phishing_site_record):
        result = ConverterToStix(mock_helper).convert_phishing_site(
            sample_phishing_site_record
        )
        types = {o.type for o in result}
        assert {"url", "domain-name", "indicator", "relationship"} <= types

    def test_empty_url(self, mock_helper):
        assert not ConverterToStix(mock_helper).convert_phishing_site({"url": ""})

    def test_phishing_label(self, mock_helper, sample_phishing_site_record):
        result = ConverterToStix(mock_helper).convert_phishing_site(
            sample_phishing_site_record
        )
        ind = [o for o in result if o.type == "indicator"][0]
        assert "phishing" in ind.labels

    def test_ip_host_no_domain_obs(self, mock_helper):
        record = {
            "url": "http://1.2.3.4/phish",
            "ip_addresses": [],
            "created": "2026-01-01T00:00:00Z",
        }
        result = ConverterToStix(mock_helper).convert_phishing_site(record)
        assert not any(o.type == "domain-name" for o in result)

    def test_ip_addresses_ipv4(self, mock_helper):
        record = {
            "url": "http://evil.com",
            "ip_addresses": ["1.2.3.4"],
            "created": "2026-01-01T00:00:00Z",
        }
        result = ConverterToStix(mock_helper).convert_phishing_site(record)
        assert any(o.type == "ipv4-addr" for o in result)

    def test_ip_addresses_ipv6(self, mock_helper):
        record = {
            "url": "http://evil.com",
            "ip_addresses": ["2001:db8::1"],
            "created": "2026-01-01T00:00:00Z",
        }
        result = ConverterToStix(mock_helper).convert_phishing_site(record)
        assert any(o.type == "ipv6-addr" for o in result)

    def test_empty_ip_string_skipped(self, mock_helper):
        record = {
            "url": "http://evil.com",
            "ip_addresses": [""],
            "created": "2026-01-01T00:00:00Z",
        }
        result = ConverterToStix(mock_helper).convert_phishing_site(record)
        assert not any(o.type == "ipv4-addr" for o in result)

    def test_url_without_scheme(self, mock_helper):
        record = {
            "url": "evil.com/phish",
            "ip_addresses": [],
            "created": "2026-01-01T00:00:00Z",
        }
        result = ConverterToStix(mock_helper).convert_phishing_site(record)
        assert any(o.type == "domain-name" for o in result)


# =====================================================================
# Malware Hash conversion
# =====================================================================


class TestConvertMalwareHash:
    def test_full_record(self, mock_helper, sample_malware_hash_record):
        result = ConverterToStix(mock_helper).convert_malware_hash(
            sample_malware_hash_record
        )
        types = {o.type for o in result}
        assert {"file", "indicator", "malware", "relationship"} <= types

    def test_empty_hashes(self, mock_helper):
        assert not ConverterToStix(mock_helper).convert_malware_hash(
            {"hashes": {}, "tags": []}
        )

    def test_no_tags_indicator_name(self, mock_helper):
        record = {
            "hashes": {"sha256": "a" * 64},
            "tags": [],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
        }
        result = ConverterToStix(mock_helper).convert_malware_hash(record)
        ind = [o for o in result if o.type == "indicator"][0]
        assert "..." in ind.name  # truncated hash


# =====================================================================
# Compromised Credential conversion
# =====================================================================


class TestConvertCompromisedCredential:
    def test_full_with_victim(self, mock_helper, sample_compromised_credential_record):
        result = ConverterToStix(mock_helper).convert_compromised_credential(
            sample_compromised_credential_record
        )
        types = {o.type for o in result}
        assert {
            "user-account",
            "url",
            "domain-name",
            "ipv4-addr",
            "incident",
            "malware",
            "relationship",
            "note",
        } <= types

    def test_incident_related_to_user_account(
        self, mock_helper, sample_compromised_credential_record
    ):
        # OpenCTI schema forbids `targets` from an Incident (SDO) to a
        # UserAccount (SCO); `related-to` is the correct relationship type.
        result = ConverterToStix(mock_helper).convert_compromised_credential(
            sample_compromised_credential_record
        )
        incident = next(o for o in result if o.type == "incident")
        user_account = next(o for o in result if o.type == "user-account")
        rels = [
            o
            for o in result
            if o.type == "relationship"
            and o.relationship_type == "related-to"
            and o.source_ref == incident.id
            and o.target_ref == user_account.id
        ]
        assert len(rels) == 1

    def test_incident_uses_malware(
        self, mock_helper, sample_compromised_credential_record
    ):
        result = ConverterToStix(mock_helper).convert_compromised_credential(
            sample_compromised_credential_record
        )
        incident = next(o for o in result if o.type == "incident")
        malware = next(o for o in result if o.type == "malware")
        uses_rels = [
            o
            for o in result
            if o.type == "relationship"
            and o.relationship_type == "uses"
            and o.source_ref == incident.id
            and o.target_ref == malware.id
        ]
        assert len(uses_rels) == 1

    def test_empty_username(self, mock_helper):
        assert not ConverterToStix(mock_helper).convert_compromised_credential(
            {"content": {"username": ""}}
        )

    def test_no_victim_detail(
        self, mock_helper, sample_compromised_credential_no_victim
    ):
        result = ConverterToStix(mock_helper).convert_compromised_credential(
            sample_compromised_credential_no_victim
        )
        types = {o.type for o in result}
        assert "user-account" in types
        assert "note" not in types
        assert "malware" not in types

    def test_no_raw_password(self, mock_helper, sample_compromised_credential_record):
        result = ConverterToStix(mock_helper).convert_compromised_credential(
            sample_compromised_credential_record
        )
        for obj in result:
            assert "t3stPassw0rd!" not in str(obj)

    def test_store_password_when_flag_enabled(
        self, mock_helper, sample_compromised_credential_record
    ):
        c = ConverterToStix(mock_helper, store_credential_password=True)
        result = c.convert_compromised_credential(sample_compromised_credential_record)
        user_accounts = [o for o in result if o.type == "user-account"]
        assert len(user_accounts) == 1
        assert user_accounts[0].credential == "t3stPassw0rd!"

    def test_corporate_label(self, mock_helper, sample_compromised_credential_record):
        result = ConverterToStix(mock_helper).convert_compromised_credential(
            sample_compromised_credential_record
        )
        inc = [o for o in result if o.type == "incident"][0]
        assert "corporate" in inc.labels

    def test_non_corporate(self, mock_helper):
        record = {
            "id": 1,
            "created": "2026-01-01T00:00:00Z",
            "company": {},
            "content": {
                "username": "u",
                "password": "p",
                "url": "",
                "source": "malware",
                "is_corporate": False,
                "password_complexity": {},
                "victim_detail": None,
            },
        }
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        inc = [o for o in result if o.type == "incident"][0]
        assert "corporate" not in inc.labels

    def test_user_account_corporate_label(
        self, mock_helper, sample_compromised_credential_record
    ):
        result = ConverterToStix(mock_helper).convert_compromised_credential(
            sample_compromised_credential_record
        )
        ua = next(o for o in result if o.type == "user-account")
        ua_labels = ua.get("x_opencti_labels", [])
        assert "corporate" in ua_labels

    def test_user_account_personal_label(self, mock_helper):
        record = {
            "id": 1,
            "created": "2026-01-01T00:00:00Z",
            "company": {},
            "content": {
                "username": "u@example.com",
                "password": "p",
                "url": "",
                "source": "malware",
                "is_corporate": False,
                "password_complexity": {},
                "victim_detail": None,
            },
        }
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        ua = next(o for o in result if o.type == "user-account")
        ua_labels = ua.get("x_opencti_labels", [])
        assert "personal" in ua_labels
        assert "corporate" not in ua_labels

    def test_user_account_source_label(self, mock_helper):
        record = {
            "id": 1,
            "created": "2026-01-01T00:00:00Z",
            "company": {},
            "content": {
                "username": "u@example.com",
                "password": "p",
                "url": "",
                "source": "phishing_site",
                "is_corporate": False,
                "password_complexity": {},
                "victim_detail": None,
            },
        }
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        ua = next(o for o in result if o.type == "user-account")
        ua_labels = ua.get("x_opencti_labels", [])
        assert "phishing-site" in ua_labels

    def test_user_account_password_strength_label(self, mock_helper):
        record = {
            "id": 1,
            "created": "2026-01-01T00:00:00Z",
            "company": {},
            "content": {
                "username": "u@example.com",
                "password": "p",
                "url": "",
                "source": "malware",
                "is_corporate": True,
                "password_complexity": {"score": "weak", "length": 6},
                "victim_detail": None,
            },
        }
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        ua = next(o for o in result if o.type == "user-account")
        ua_labels = ua.get("x_opencti_labels", [])
        assert "password-strength-weak" in ua_labels

    def test_no_target_url(self, mock_helper):
        record = {
            "id": 1,
            "created": "2026-01-01T00:00:00Z",
            "company": {},
            "content": {
                "username": "u",
                "password": "p",
                "url": "",
                "source": "x",
                "is_corporate": False,
                "password_complexity": {},
                "victim_detail": None,
            },
        }
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        assert not any(o.type == "url" for o in result)

    def test_victim_ipv6(self, mock_helper):
        record = {
            "id": 1,
            "created": "2026-01-01T00:00:00Z",
            "company": {},
            "content": {
                "username": "u",
                "password": "p",
                "url": "",
                "source": "x",
                "is_corporate": False,
                "password_complexity": {},
                "victim_detail": {"ip": "2001:db8::1", "malware": "X"},
            },
        }
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        assert any(o.type == "ipv6-addr" for o in result)

    def test_victim_invalid_ip(self, mock_helper):
        record = {
            "id": 1,
            "created": "2026-01-01T00:00:00Z",
            "company": {},
            "content": {
                "username": "u",
                "password": "p",
                "url": "",
                "source": "x",
                "is_corporate": False,
                "password_complexity": {},
                "victim_detail": {"ip": "not-ip", "malware": None},
            },
        }
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        assert not any(o.type in ("ipv4-addr", "ipv6-addr") for o in result)

    def test_victim_empty_ip(self, mock_helper):
        record = {
            "id": 1,
            "created": "2026-01-01T00:00:00Z",
            "company": {},
            "content": {
                "username": "u",
                "password": "p",
                "url": "",
                "source": "x",
                "is_corporate": False,
                "password_complexity": {},
                "victim_detail": {"ip": ""},
            },
        }
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        assert not any(o.type in ("ipv4-addr", "ipv6-addr") for o in result)

    def test_no_password_complexity(self, mock_helper):
        record = {
            "id": 1,
            "created": "2026-01-01T00:00:00Z",
            "company": {},
            "content": {
                "username": "u",
                "password": "p",
                "url": "",
                "source": "x",
                "is_corporate": False,
                "password_complexity": None,
                "victim_detail": None,
            },
        }
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        assert any(o.type == "incident" for o in result)

    def test_deterministic(self, mock_helper, sample_compromised_credential_record):
        c = ConverterToStix(mock_helper)
        assert {
            o.id
            for o in c.convert_compromised_credential(
                sample_compromised_credential_record
            )
        } == {
            o.id
            for o in c.convert_compromised_credential(
                sample_compromised_credential_record
            )
        }

    def test_target_url_with_ip_host(self, mock_helper):
        """Target URL whose hostname is an IP → no domain-name created."""
        record = {
            "id": 1,
            "created": "2026-01-01T00:00:00Z",
            "company": {},
            "content": {
                "username": "u",
                "password": "p",
                "url": "http://10.0.0.1/login",
                "source": "x",
                "is_corporate": False,
                "password_complexity": {},
                "victim_detail": None,
            },
        }
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        assert not any(o.type == "domain-name" for o in result)


# =====================================================================
# Credit Card Ticket conversion
# =====================================================================


class TestStripHtml:
    def test_removes_tags(self):
        assert ConverterToStix._strip_html("<p>Hello</p>") == "Hello"

    def test_br_becomes_newline(self):
        result = ConverterToStix._strip_html("line1<br/>line2")
        assert "line1" in result and "line2" in result

    def test_unescape_entities(self):
        assert "&amp;" not in ConverterToStix._strip_html("&amp;")
        assert "&" in ConverterToStix._strip_html("&amp;")

    def test_empty_string(self):
        assert ConverterToStix._strip_html("") == ""

    def test_none_returns_empty(self):
        assert ConverterToStix._strip_html(None) == ""  # type: ignore


# =====================================================================
# Deep Sight Ticket conversion
# =====================================================================


class TestConvertDeepSightTicket:
    def test_full_record(self, mock_helper, sample_deep_sight_ticket_record):
        result = ConverterToStix(mock_helper).convert_deep_sight_ticket(
            sample_deep_sight_ticket_record
        )
        types = {o.type for o in result}
        assert {"threat-actor", "identity", "relationship", "report"} <= types

    def test_no_actors_no_targets(
        self, mock_helper, sample_deep_sight_ticket_no_actors_no_targets
    ):
        result = ConverterToStix(mock_helper).convert_deep_sight_ticket(
            sample_deep_sight_ticket_no_actors_no_targets
        )
        types = {o.type for o in result}
        assert "report" in types
        assert "threat-actor" not in types
        assert "identity" not in types
        # Report must have at least one object_ref (fallback to author)
        rep = [o for o in result if o.type == "report"][0]
        assert len(rep.object_refs) >= 1

    def test_per_record_tlp_amber(self, mock_helper, sample_deep_sight_ticket_record):
        """amber TLP in content must be applied to all objects in the ticket."""
        import stix2

        c = ConverterToStix(mock_helper, tlp_level="red")  # connector default = red
        result = c.convert_deep_sight_ticket(sample_deep_sight_ticket_record)
        for obj in result:
            markings = getattr(obj, "object_marking_refs", None)
            if markings:
                assert stix2.TLP_AMBER.id in markings

    def test_per_record_tlp_red(
        self, mock_helper, sample_deep_sight_ticket_with_report
    ):
        import stix2

        c = ConverterToStix(mock_helper, tlp_level="amber")  # connector default = amber
        result = c.convert_deep_sight_ticket(sample_deep_sight_ticket_with_report)
        for obj in result:
            markings = getattr(obj, "object_marking_refs", None)
            if markings:
                assert stix2.TLP_RED.id in markings

    def test_targets_relationship(self, mock_helper, sample_deep_sight_ticket_record):
        result = ConverterToStix(mock_helper).convert_deep_sight_ticket(
            sample_deep_sight_ticket_record
        )
        rels = [o for o in result if o.type == "relationship"]
        assert any(r.relationship_type == "targets" for r in rels)

    def test_labels_from_content(self, mock_helper, sample_deep_sight_ticket_record):
        result = ConverterToStix(mock_helper).convert_deep_sight_ticket(
            sample_deep_sight_ticket_record
        )
        rep = [o for o in result if o.type == "report"][0]
        assert "ransomware" in rep.labels
        assert "regional" in rep.labels

    def test_motivation_mapped(self, mock_helper, sample_deep_sight_ticket_record):
        result = ConverterToStix(mock_helper).convert_deep_sight_ticket(
            sample_deep_sight_ticket_record
        )
        ta = [o for o in result if o.type == "threat-actor"][0]
        assert ta.primary_motivation == "ideology"

    def test_multiple_motivations(self, mock_helper):
        record = {
            "id": 1,
            "status": "open",
            "created": "2026-01-01T00:00:00Z",
            "content": {
                "title": "Test",
                "analyst_notes": "",
                "threat_actors": [
                    {"nickname": "TestActor", "motivations": ["money", "ideological"]}
                ],
                "targets": [],
                "tlp": "amber",
                "labels": [],
                "markers": [],
            },
        }
        result = ConverterToStix(mock_helper).convert_deep_sight_ticket(record)
        ta = [o for o in result if o.type == "threat-actor"][0]
        assert ta.primary_motivation == "personal-gain"
        assert "ideology" in ta.secondary_motivations

    def test_na_nickname_skipped(self, mock_helper):
        record = {
            "id": 1,
            "status": "open",
            "created": "2026-01-01T00:00:00Z",
            "content": {
                "title": "Test",
                "analyst_notes": "",
                "threat_actors": [{"nickname": "N/A", "motivations": []}],
                "targets": [],
                "tlp": "amber",
                "labels": [],
                "markers": [],
            },
        }
        result = ConverterToStix(mock_helper).convert_deep_sight_ticket(record)
        assert not any(o.type == "threat-actor" for o in result)

    def test_na_target_skipped(self, mock_helper):
        record = {
            "id": 1,
            "status": "open",
            "created": "2026-01-01T00:00:00Z",
            "content": {
                "title": "Test",
                "analyst_notes": "",
                "threat_actors": [],
                "targets": [{"name": "N/A", "risk_score": "low"}],
                "tlp": "amber",
                "labels": [],
                "markers": [],
            },
        }
        result = ConverterToStix(mock_helper).convert_deep_sight_ticket(record)
        assert not any(o.type == "identity" for o in result)

    def test_html_stripped_in_description(self, mock_helper):
        record = {
            "id": 1,
            "status": "open",
            "created": "2026-01-01T00:00:00Z",
            "content": {
                "title": "Test",
                "analyst_notes": "<p>Clean text here.</p>",
                "threat_actors": [],
                "targets": [],
                "tlp": "green",
                "labels": [],
                "markers": [],
            },
        }
        result = ConverterToStix(mock_helper).convert_deep_sight_ticket(record)
        rep = [o for o in result if o.type == "report"][0]
        assert "<p>" not in rep.description
        assert "Clean text here." in rep.description

    def test_deterministic_ids(self, mock_helper, sample_deep_sight_ticket_record):
        c = ConverterToStix(mock_helper)
        ids1 = {
            o.id for o in c.convert_deep_sight_ticket(sample_deep_sight_ticket_record)
        }
        ids2 = {
            o.id for o in c.convert_deep_sight_ticket(sample_deep_sight_ticket_record)
        }
        assert ids1 == ids2

    def test_pdf_embedded_in_x_opencti_files(self, mock_helper):
        """When _pdf_data/_pdf_filename are present, the Report gets x_opencti_files."""
        import base64

        record = {
            "id": 99,
            "status": "open",
            "created": "2026-01-01T00:00:00Z",
            "content": {
                "title": "Test Report With PDF",
                "analyst_notes": "",
                "threat_actors": [],
                "targets": [],
                "tlp": "amber",
                "labels": [],
                "markers": [],
            },
            "_pdf_data": b"%PDF-1.4 fake content",
            "_pdf_filename": "report_99.pdf",
        }
        c = ConverterToStix(mock_helper)
        result = c.convert_deep_sight_ticket(record)
        rep = [o for o in result if o.type == "report"][0]
        files = rep.get("x_opencti_files")
        assert files is not None and len(files) == 1
        f = files[0]
        assert f["name"] == "report_99.pdf"
        assert f["mime_type"] == "application/pdf"
        assert f["no_trigger_import"] is True
        assert base64.b64decode(f["data"]) == b"%PDF-1.4 fake content"

    def test_no_pdf_no_x_opencti_files(
        self, mock_helper, sample_deep_sight_ticket_record
    ):
        """When no _pdf_data is present, x_opencti_files must not be in the Report."""
        # sample_deep_sight_ticket_record has report: None so no PDF
        c = ConverterToStix(mock_helper)
        result = c.convert_deep_sight_ticket(sample_deep_sight_ticket_record)
        rep = [o for o in result if o.type == "report"][0]
        assert rep.get("x_opencti_files") is None

    def test_has_attachment_label(
        self, mock_helper, sample_deep_sight_ticket_with_report
    ):
        """Records with a non-null report URL get the 'has-attachment' label."""
        c = ConverterToStix(mock_helper)
        result = c.convert_deep_sight_ticket(sample_deep_sight_ticket_with_report)
        rep = [o for o in result if o.type == "report"][0]
        assert "has-attachment" in rep.labels
        assert "no-attachment" not in rep.labels

    def test_no_attachment_label(self, mock_helper, sample_deep_sight_ticket_record):
        """Records with report: null get the 'no-attachment' label."""
        # sample_deep_sight_ticket_record has report: None
        c = ConverterToStix(mock_helper)
        result = c.convert_deep_sight_ticket(sample_deep_sight_ticket_record)
        rep = [o for o in result if o.type == "report"][0]
        assert "no-attachment" in rep.labels
        assert "has-attachment" not in rep.labels


class TestConvertCreditCardTicket:
    def test_full_record(self, mock_helper, sample_credit_card_record):
        result = ConverterToStix(mock_helper).convert_credit_card_ticket(
            sample_credit_card_record
        )
        types = {o.type for o in result}
        assert {"incident", "identity", "relationship", "note"} <= types

    def test_empty_card(self, mock_helper):
        assert not ConverterToStix(mock_helper).convert_credit_card_ticket(
            {"content": {"number": ""}}
        )

    def test_pan_never_stored(self, mock_helper, sample_credit_card_record):
        for obj in ConverterToStix(mock_helper).convert_credit_card_ticket(
            sample_credit_card_record
        ):
            assert "4242424242424242" not in str(obj)

    def test_masked_in_description(self, mock_helper, sample_credit_card_record):
        result = ConverterToStix(mock_helper).convert_credit_card_ticket(
            sample_credit_card_record
        )
        inc = [o for o in result if o.type == "incident"][0]
        assert "424242" in inc.description
        assert "4242" in inc.description

    def test_targets_relationship(self, mock_helper, sample_credit_card_record):
        result = ConverterToStix(mock_helper).convert_credit_card_ticket(
            sample_credit_card_record
        )
        assert any(
            o.type == "relationship" and o.relationship_type == "targets"
            for o in result
        )

    def test_deterministic(self, mock_helper, sample_credit_card_record):
        c = ConverterToStix(mock_helper)
        assert {
            o.id for o in c.convert_credit_card_ticket(sample_credit_card_record)
        } == {o.id for o in c.convert_credit_card_ticket(sample_credit_card_record)}
