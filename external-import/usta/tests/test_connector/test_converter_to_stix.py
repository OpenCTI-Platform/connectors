"""Unit tests for the USTA Prodaft STIX converter — 100 % branch coverage."""

import pytest
from unittest.mock import MagicMock
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
        assert (ConverterToStix(mock_helper, author_name="A").author.id
                == ConverterToStix(mock_helper, author_name="A").author.id)


# =====================================================================
# Static / internal helpers
# =====================================================================

class TestParseDatetime:
    def test_none_returns_now(self, mock_helper):
        result = ConverterToStix._parse_datetime(None)
        assert result.endswith("Z")

    def test_plus_utc_suffix_replaced(self, mock_helper):
        assert ConverterToStix._parse_datetime("2026-01-01T00:00:00+00:00") == "2026-01-01T00:00:00Z"

    def test_normal_passthrough(self, mock_helper):
        assert ConverterToStix._parse_datetime("2026-01-01T00:00:00Z") == "2026-01-01T00:00:00Z"


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
        assert ConverterToStix._main_observable_type(True, "evil.com", []) == "Domain-Name"

    def test_ip_addresses(self):
        assert ConverterToStix._main_observable_type(False, "", ["1.2.3.4"]) == "IPv4-Addr"

    def test_host_ipv4(self):
        assert ConverterToStix._main_observable_type(False, "1.2.3.4", []) == "IPv4-Addr"

    def test_host_ipv6(self):
        assert ConverterToStix._main_observable_type(False, "::1", []) == "IPv6-Addr"

    def test_host_domain_fallback(self):
        assert ConverterToStix._main_observable_type(False, "evil.com", []) == "Domain-Name"

    def test_nothing(self):
        assert ConverterToStix._main_observable_type(False, "", []) == "Url"


class TestMaskCardNumber:
    def test_standard_16(self):
        assert ConverterToStix._mask_card_number("4289691967078106") == "428969******8106"

    def test_short_card(self):
        assert ConverterToStix._mask_card_number("12345") == "*****"

    def test_with_spaces_and_dashes(self):
        assert ConverterToStix._mask_card_number("4289-6919-6707-8106") == "428969******8106"


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
            sha256="285f7b8f2bbee896cf8a14af480f1f09811bdcd6cd2abff12a0046a0d286f131"
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
        a1 = c._create_user_account_observable("user@test.com")
        a2 = c._create_user_account_observable("user@test.com")
        assert a1.id == a2.id
        assert a1.account_login == "user@test.com"


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
        assert ConverterToStix(mock_helper).convert_malicious_url({"url": ""}) == []

    def test_domain_based(self, mock_helper):
        record = {"url": "evil.com:443", "host": "evil.com", "is_domain": True,
                  "ip_addresses": [], "tags": [], "valid_from": "2026-01-01T00:00:00Z",
                  "valid_until": "2027-01-01T00:00:00Z"}
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        types = {o.type for o in result}
        assert "domain-name" in types

    def test_ipv6_in_ip_addresses(self, mock_helper):
        record = {"url": "[::1]:80", "host": "::1", "is_domain": False,
                  "ip_addresses": ["2001:db8::1"], "tags": [],
                  "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z"}
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        types = {o.type for o in result}
        assert "ipv6-addr" in types

    def test_host_only_ip_fallback(self, mock_helper):
        """No ip_addresses, not domain, host is an IP → uses host."""
        record = {"url": "10.0.0.1:80", "host": "10.0.0.1", "is_domain": False,
                  "ip_addresses": [], "tags": [], "valid_from": "2026-01-01T00:00:00Z",
                  "valid_until": "2027-01-01T00:00:00Z"}
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        types = {o.type for o in result}
        assert "ipv4-addr" in types

    def test_host_only_domain_fallback(self, mock_helper):
        """No ip_addresses, not is_domain flag, host is a domain string."""
        record = {"url": "bad.org", "host": "bad.org", "is_domain": True,
                  "ip_addresses": [], "tags": [], "valid_from": "2026-01-01T00:00:00Z",
                  "valid_until": "2027-01-01T00:00:00Z"}
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        types = {o.type for o in result}
        assert "domain-name" in types

    def test_host_not_ip(self, mock_helper):
        """No ip_addresses, not is_domain flag, host is filled."""
        record = {"url": "http://example.com", "host": "example.com", "is_domain": False, 
                  "ip_addresses": [], "tags": [], "valid_from": "2026-01-01T00:00:00Z",
                  "valid_until": "2027-01-01T00:00:00Z"}
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        types = {o.type for o in result}
        assert "domain-name" in types

    def test_convert_malicious_url_fallback_no_scheme(self, mock_helper):
        converter = ConverterToStix(mock_helper)
        
        converter._extract_host = MagicMock(return_value="")
        converter._is_ip = MagicMock(return_value=False)
        
        # Act as path in URL and no host
        record = {
            "url": "/api/v1/malware", 
            "host": "", 
            "is_domain": False,
            "ip_addresses": [],
            "tags": ["test"],
            "valid_from": "2026-01-01T00:00:00Z"
        }
        
        result = converter.convert_malicious_url(record)
        
        indicator = next(o for o in result if o["type"] == "indicator")
        assert "url:value = 'http:///api/v1/malware'" in indicator["pattern"]

    def test_convert_malicious_url_fallback_with_scheme(self, mock_helper):
        converter = ConverterToStix(mock_helper)
        converter._extract_host = MagicMock(return_value="")
        converter._is_ip = MagicMock(return_value=False)
        
        record = {
            "url": "https://unknown-format-url.com", 
            "host": "", 
            "is_domain": False,
            "ip_addresses": [],
            "valid_from": "2026-01-01T00:00:00Z"
        }
        
        result = converter.convert_malicious_url(record)
        
        indicator = next(o for o in result if o["type"] == "indicator")
        assert "url:value = 'https://unknown-format-url.com'" in indicator["pattern"]


    def test_multiple_ips_or_pattern(self, mock_helper):
        """Two IPs → OR-joined pattern."""
        record = {"url": "1.1.1.1:80", "host": "", "is_domain": False,
                  "ip_addresses": ["1.1.1.1", "2.2.2.2"], "tags": [],
                  "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z"}
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        indicators = [o for o in result if o.type == "indicator"]
        assert " OR " in indicators[0].pattern

    def test_invalid_ip_in_list_skipped(self, mock_helper):
        record = {"url": "x:80", "host": "", "is_domain": True,
                  "ip_addresses": ["not-an-ip"], "tags": [],
                  "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z"}
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        # No observable created for invalid IP, falls back to URL pattern
        indicators = [o for o in result if o.type == "indicator"]
        assert len(indicators) == 1

    def test_url_without_slash_or_colon_no_extra_url_obs(self, mock_helper):
        record = {"url": "plaintext", "host": "", "is_domain": True,
                  "ip_addresses": [], "tags": [], "valid_from": "2026-01-01T00:00:00Z",
                  "valid_until": "2027-01-01T00:00:00Z"}
        result = ConverterToStix(mock_helper).convert_malicious_url(record)
        url_obs = [o for o in result if o.type == "url"]
        assert len(url_obs) == 0

    def test_tags_produce_malware_and_relationship(self, mock_helper, sample_malicious_url_record):
        result = ConverterToStix(mock_helper).convert_malicious_url(sample_malicious_url_record)
        assert any(o.type == "malware" and o.name == "Ghost RAT" for o in result)
        rel_types = {o.relationship_type for o in result if o.type == "relationship"}
        assert "indicates" in rel_types
        assert "based-on" in rel_types

    def test_deterministic_ids(self, mock_helper, sample_malicious_url_record):
        c = ConverterToStix(mock_helper)
        assert {o.id for o in c.convert_malicious_url(sample_malicious_url_record)} == \
               {o.id for o in c.convert_malicious_url(sample_malicious_url_record)}


# =====================================================================
# Phishing Site conversion
# =====================================================================

class TestConvertPhishingSite:
    def test_basic(self, mock_helper, sample_phishing_site_record):
        result = ConverterToStix(mock_helper).convert_phishing_site(sample_phishing_site_record)
        types = {o.type for o in result}
        assert {"url", "domain-name", "indicator", "relationship"} <= types

    def test_empty_url(self, mock_helper):
        assert ConverterToStix(mock_helper).convert_phishing_site({"url": ""}) == []

    def test_phishing_label(self, mock_helper, sample_phishing_site_record):
        result = ConverterToStix(mock_helper).convert_phishing_site(sample_phishing_site_record)
        ind = [o for o in result if o.type == "indicator"][0]
        assert "phishing" in ind.labels

    def test_ip_host_no_domain_obs(self, mock_helper):
        record = {"url": "http://1.2.3.4/phish", "ip_addresses": [], "created": "2026-01-01T00:00:00Z"}
        result = ConverterToStix(mock_helper).convert_phishing_site(record)
        assert not any(o.type == "domain-name" for o in result)

    def test_ip_addresses_ipv4(self, mock_helper):
        record = {"url": "http://evil.com", "ip_addresses": ["1.2.3.4"],
                  "created": "2026-01-01T00:00:00Z"}
        result = ConverterToStix(mock_helper).convert_phishing_site(record)
        assert any(o.type == "ipv4-addr" for o in result)

    def test_ip_addresses_ipv6(self, mock_helper):
        record = {"url": "http://evil.com", "ip_addresses": ["2001:db8::1"],
                  "created": "2026-01-01T00:00:00Z"}
        result = ConverterToStix(mock_helper).convert_phishing_site(record)
        assert any(o.type == "ipv6-addr" for o in result)

    def test_empty_ip_string_skipped(self, mock_helper):
        record = {"url": "http://evil.com", "ip_addresses": [""],
                  "created": "2026-01-01T00:00:00Z"}
        result = ConverterToStix(mock_helper).convert_phishing_site(record)
        assert not any(o.type == "ipv4-addr" for o in result)

    def test_url_without_scheme(self, mock_helper):
        record = {"url": "evil.com/phish", "ip_addresses": [], "created": "2026-01-01T00:00:00Z"}
        result = ConverterToStix(mock_helper).convert_phishing_site(record)
        assert any(o.type == "domain-name" for o in result)


# =====================================================================
# Malware Hash conversion
# =====================================================================

class TestConvertMalwareHash:
    def test_full_record(self, mock_helper, sample_malware_hash_record):
        result = ConverterToStix(mock_helper).convert_malware_hash(sample_malware_hash_record)
        types = {o.type for o in result}
        assert {"file", "indicator", "malware", "relationship"} <= types

    def test_empty_hashes(self, mock_helper):
        assert ConverterToStix(mock_helper).convert_malware_hash({"hashes": {}, "tags": []}) == []

    def test_no_tags_indicator_name(self, mock_helper):
        record = {"hashes": {"sha256": "a" * 64}, "tags": [],
                  "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z"}
        result = ConverterToStix(mock_helper).convert_malware_hash(record)
        ind = [o for o in result if o.type == "indicator"][0]
        assert "..." in ind.name  # truncated hash


# =====================================================================
# Compromised Credential conversion
# =====================================================================

class TestConvertCompromisedCredential:
    def test_full_with_victim(self, mock_helper, sample_compromised_credential_record):
        result = ConverterToStix(mock_helper).convert_compromised_credential(
            sample_compromised_credential_record)
        types = {o.type for o in result}
        assert {"user-account", "url", "domain-name", "ipv4-addr",
                "indicator", "malware", "relationship", "note"} <= types

    def test_empty_username(self, mock_helper):
        assert ConverterToStix(mock_helper).convert_compromised_credential(
            {"content": {"username": ""}}) == []

    def test_no_victim_detail(self, mock_helper, sample_compromised_credential_no_victim):
        result = ConverterToStix(mock_helper).convert_compromised_credential(
            sample_compromised_credential_no_victim)
        types = {o.type for o in result}
        assert "user-account" in types
        assert "note" not in types
        assert "malware" not in types

    def test_no_raw_password(self, mock_helper, sample_compromised_credential_record):
        result = ConverterToStix(mock_helper).convert_compromised_credential(
            sample_compromised_credential_record)
        for obj in result:
            assert "h282002h" not in str(obj)

    def test_corporate_label(self, mock_helper, sample_compromised_credential_record):
        result = ConverterToStix(mock_helper).convert_compromised_credential(
            sample_compromised_credential_record)
        ind = [o for o in result if o.type == "indicator"][0]
        assert "corporate" in ind.labels

    def test_non_corporate(self, mock_helper):
        record = {"id": 1, "created": "2026-01-01T00:00:00Z", "company": {},
                  "content": {"username": "u", "password": "p", "url": "",
                              "source": "malware", "is_corporate": False,
                              "password_complexity": {}, "victim_detail": None}}
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        ind = [o for o in result if o.type == "indicator"][0]
        assert "corporate" not in ind.labels

    def test_no_target_url(self, mock_helper):
        record = {"id": 1, "created": "2026-01-01T00:00:00Z", "company": {},
                  "content": {"username": "u", "password": "p", "url": "",
                              "source": "x", "is_corporate": False,
                              "password_complexity": {}, "victim_detail": None}}
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        assert not any(o.type == "url" for o in result)

    def test_victim_ipv6(self, mock_helper):
        record = {"id": 1, "created": "2026-01-01T00:00:00Z", "company": {},
                  "content": {"username": "u", "password": "p", "url": "",
                              "source": "x", "is_corporate": False,
                              "password_complexity": {},
                              "victim_detail": {"ip": "2001:db8::1", "malware": "X"}}}
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        assert any(o.type == "ipv6-addr" for o in result)

    def test_victim_invalid_ip(self, mock_helper):
        record = {"id": 1, "created": "2026-01-01T00:00:00Z", "company": {},
                  "content": {"username": "u", "password": "p", "url": "",
                              "source": "x", "is_corporate": False,
                              "password_complexity": {},
                              "victim_detail": {"ip": "not-ip", "malware": None}}}
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        assert not any(o.type in ("ipv4-addr", "ipv6-addr") for o in result)

    def test_victim_empty_ip(self, mock_helper):
        record = {"id": 1, "created": "2026-01-01T00:00:00Z", "company": {},
                  "content": {"username": "u", "password": "p", "url": "",
                              "source": "x", "is_corporate": False,
                              "password_complexity": {},
                              "victim_detail": {"ip": ""}}}
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        assert not any(o.type in ("ipv4-addr", "ipv6-addr") for o in result)

    def test_no_password_complexity(self, mock_helper):
        record = {"id": 1, "created": "2026-01-01T00:00:00Z", "company": {},
                  "content": {"username": "u", "password": "p", "url": "",
                              "source": "x", "is_corporate": False,
                              "password_complexity": None, "victim_detail": None}}
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        assert any(o.type == "indicator" for o in result)

    def test_deterministic(self, mock_helper, sample_compromised_credential_record):
        c = ConverterToStix(mock_helper)
        assert ({o.id for o in c.convert_compromised_credential(sample_compromised_credential_record)}
                == {o.id for o in c.convert_compromised_credential(sample_compromised_credential_record)})

    def test_target_url_with_ip_host(self, mock_helper):
        """Target URL whose hostname is an IP → no domain-name created."""
        record = {"id": 1, "created": "2026-01-01T00:00:00Z", "company": {},
                  "content": {"username": "u", "password": "p",
                              "url": "http://10.0.0.1/login",
                              "source": "x", "is_corporate": False,
                              "password_complexity": {}, "victim_detail": None}}
        result = ConverterToStix(mock_helper).convert_compromised_credential(record)
        assert not any(o.type == "domain-name" for o in result)


# =====================================================================
# Credit Card Ticket conversion
# =====================================================================

class TestConvertCreditCardTicket:
    def test_full_record(self, mock_helper, sample_credit_card_record):
        result = ConverterToStix(mock_helper).convert_credit_card_ticket(sample_credit_card_record)
        types = {o.type for o in result}
        assert {"incident", "identity", "relationship", "note"} <= types

    def test_empty_card(self, mock_helper):
        assert ConverterToStix(mock_helper).convert_credit_card_ticket(
            {"content": {"number": ""}}) == []

    def test_pan_never_stored(self, mock_helper, sample_credit_card_record):
        for obj in ConverterToStix(mock_helper).convert_credit_card_ticket(sample_credit_card_record):
            assert "4289691967078106" not in str(obj)

    def test_masked_in_description(self, mock_helper, sample_credit_card_record):
        result = ConverterToStix(mock_helper).convert_credit_card_ticket(sample_credit_card_record)
        inc = [o for o in result if o.type == "incident"][0]
        assert "428969" in inc.description
        assert "8106" in inc.description

    def test_targets_relationship(self, mock_helper, sample_credit_card_record):
        result = ConverterToStix(mock_helper).convert_credit_card_ticket(sample_credit_card_record)
        assert any(o.type == "relationship" and o.relationship_type == "targets" for o in result)

    def test_deterministic(self, mock_helper, sample_credit_card_record):
        c = ConverterToStix(mock_helper)
        assert ({o.id for o in c.convert_credit_card_ticket(sample_credit_card_record)}
                == {o.id for o in c.convert_credit_card_ticket(sample_credit_card_record)})
