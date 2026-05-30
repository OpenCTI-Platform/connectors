"""Tests for the STIX converter."""

from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import ConverterToStix


@pytest.fixture
def converter():
    return ConverterToStix(helper=MagicMock())


def _types(objects):
    return [obj.type for obj in objects]


class TestConverterHelpers:
    def test_severity_to_score_known(self, converter):
        assert converter._severity_to_score("critical") == 95
        assert converter._severity_to_score("HIGH") == 80
        assert converter._severity_to_score("informational") == 10

    def test_severity_to_score_unknown(self, converter):
        assert converter._severity_to_score("banana") == 50

    def test_severity_to_priority(self, converter):
        assert converter._severity_to_priority("critical") == "P1"
        assert converter._severity_to_priority("low") == "P4"
        assert converter._severity_to_priority("unknown") == "P3"

    def test_normalize_severity(self, converter):
        assert converter._normalize_severity("HIGH") == "high"
        assert converter._normalize_severity("info") == "low"
        assert converter._normalize_severity("informational") == "low"
        assert converter._normalize_severity("weird") == "medium"

    def test_slugify_label(self, converter):
        assert converter._slugify_label("Brand Impersonation!") == "brand-impersonation"
        assert converter._slugify_label("  Phishing / Fraud  ") == "phishing-fraud"

    def test_ext_ref_without_url(self, converter):
        ref = converter._ext_ref("CTM360", 123)
        assert ref.source_name == "CTM360"
        assert ref.external_id == "123"

    def test_ext_ref_with_url(self, converter):
        ref = converter._ext_ref("CTM360", "abc", url="https://example.com")
        assert ref.url == "https://example.com"

    def test_escape_stix_value(self, converter):
        assert converter._escape_stix_value("o'brien") == "o\\'brien"
        assert converter._escape_stix_value("a\\b") == "a\\\\b"


class TestStixPatternEscaping:
    """Values embedded in STIX patterns must be escaped so stix2 accepts them."""

    def test_breached_username_with_quote(self, converter):
        objects = converter.breached_credentials_to_stix(
            [{"id": "C9", "username": "o'brien"}]
        )
        indicators = [o for o in objects if o.type == "indicator"]
        assert indicators  # stix2 would raise on an invalid pattern
        assert "o\\'brien" in indicators[0].pattern

    def test_breached_email_with_quote(self, converter):
        objects = converter.breached_credentials_to_stix(
            [{"id": "C10", "email": "o'brien@example.com"}]
        )
        indicators = [o for o in objects if o.type == "indicator"]
        assert indicators
        assert "o\\'brien@example.com" in indicators[0].pattern

    def test_domain_with_quote(self, converter):
        objects = converter.domain_protection_to_stix(
            [{"id": "D9", "domain": "ev'il.example"}]
        )
        indicators = [o for o in objects if o.type == "indicator"]
        assert indicators
        assert "ev\\'il.example" in indicators[0].pattern


class TestIncidentsToStix:
    def test_basic_incident_metadata(self, converter):
        incidents = [
            {
                "id": "INC-1",
                "subject": "Phishing site",
                "severity": "high",
                "type": "Phishing",
                "status": "open",
                "coa": "Takedown",
                "source": "DarkWeb",
                "remarks": "Urgent",
                "brand": "ACME",
                "created_date": "04-03-2026 18:29:05",
            }
        ]
        objects = converter.incidents_to_stix(incidents)

        assert _types(objects) == ["identity"]
        assert len(converter.incident_case_metadata) == 1
        meta = converter.incident_case_metadata[0]
        assert meta["ticket_id"] == "INC-1"
        assert meta["name"] == "Urgent - Phishing site [INC-1]"
        assert meta["severity"] == "high"
        assert meta["priority"] == "P2"
        assert meta["response_types"] == ["Phishing"]
        assert "phishing" in meta["labels"]
        assert "ctm360-cbs" in meta["labels"]
        assert "status:open" in meta["labels"]
        assert "coa:takedown" in meta["labels"]
        assert "Brand:ACME" in meta["labels"]
        assert "Source:DarkWeb" in meta["labels"]
        assert meta["created"] == "2026-03-04T18:29:05Z"

    def test_incident_without_remarks_name(self, converter):
        converter.incidents_to_stix(
            [{"id": "INC-2", "subject": "Lookalike", "remarks": ""}]
        )
        assert converter.incident_case_metadata[0]["name"] == "Lookalike [INC-2]"

    def test_incident_status_unknown_and_coa_none(self, converter):
        converter.incidents_to_stix(
            [{"id": "INC-3", "subject": "X", "status": "unknown", "coa": "None"}]
        )
        labels = converter.incident_case_metadata[0]["labels"]
        assert not any(label.startswith("status:") for label in labels)
        assert not any(label.startswith("coa:") for label in labels)

    def test_incident_without_id_is_skipped(self, converter):
        objects = converter.incidents_to_stix([{"subject": "no id here"}])
        assert _types(objects) == ["identity"]
        assert converter.incident_case_metadata == []
        converter.helper.connector_logger.warning.assert_called_once()

    def test_metadata_reset_between_runs(self, converter):
        converter.incidents_to_stix([{"id": "INC-A", "subject": "A"}])
        converter.incidents_to_stix([{"id": "INC-B", "subject": "B"}])
        assert len(converter.incident_case_metadata) == 1
        assert converter.incident_case_metadata[0]["ticket_id"] == "INC-B"


class TestMalwareLogsToStix:
    def test_full_log_produces_all_observables(self, converter):
        logs = [
            {
                "id": "M1",
                "malware_family": "RedLine",
                "ip": "1.2.3.4",
                "domain": "evil.example",
                "email": "victim@example.com",
                "date": "2026-03-04T18:00:00Z",
            }
        ]
        types = _types(converter.malware_logs_to_stix(logs))
        assert "malware" in types
        assert "ipv4-addr" in types
        assert "relationship" in types
        assert "domain-name" in types
        assert "email-addr" in types

    def test_unknown_family_and_invalid_ip(self, converter):
        logs = [{"id": "M2", "malware_family": "Unknown", "ip": "999.999.1.1"}]
        types = _types(converter.malware_logs_to_stix(logs))
        assert "malware" not in types
        assert "ipv4-addr" not in types

    def test_email_without_at_is_skipped(self, converter):
        logs = [{"id": "M3", "email": "notanemail"}]
        types = _types(converter.malware_logs_to_stix(logs))
        assert "email-addr" not in types

    def test_empty_log_only_author(self, converter):
        types = _types(converter.malware_logs_to_stix([{}]))
        assert types == ["identity"]


class TestBreachedCredentialsToStix:
    def test_full_credential(self, converter):
        creds = [
            {
                "id": "C1",
                "email": "jdoe@example.com",
                "username": "jdoe",
                "domain": "example.com",
                "breach_source": "LinkedIn",
                "date": "2026-03-04T18:00:00Z",
            }
        ]
        types = _types(converter.breached_credentials_to_stix(creds))
        assert "email-addr" in types
        assert "domain-name" in types
        assert "user-account" in types
        assert "indicator" in types
        assert "note" in types
        # Indicator based-on both email and user-account.
        assert types.count("relationship") == 2

    def test_username_only_uses_user_account_pattern(self, converter):
        creds = [{"id": "C2", "username": "jdoe"}]
        objects = converter.breached_credentials_to_stix(creds)
        indicators = [o for o in objects if o.type == "indicator"]
        assert indicators
        assert "user-account:account_login" in indicators[0].pattern
        # Only one based-on relationship (user-account), no email observable.
        assert _types(objects).count("relationship") == 1

    def test_no_identifiers_skips_indicator(self, converter):
        objects = converter.breached_credentials_to_stix([{"id": "C3"}])
        types = _types(objects)
        assert "indicator" not in types
        assert "user-account" in types
        assert "note" in types


class TestCardLeaksToStix:
    def test_card_leak_note(self, converter):
        objects = converter.card_leaks_to_stix(
            [{"id": "CL1", "bank_name": "ACME Bank", "date": "2026-03-04T18:00:00Z"}]
        )
        notes = [o for o in objects if o.type == "note"]
        assert len(notes) == 1
        assert "ACME Bank" in notes[0].content

    def test_card_leak_defaults(self, converter):
        objects = converter.card_leaks_to_stix([{}])
        assert any(o.type == "note" for o in objects)


class TestDomainProtectionToStix:
    def test_domain_with_ip(self, converter):
        findings = [
            {
                "id": "D1",
                "domain": "bad.example",
                "type": "typosquatting",
                "risk_score": 90,
                "finding_status": "open",
                "ip_address": "8.8.8.8",
                "created_date": "2026-03-04T18:00:00Z",
            }
        ]
        types = _types(converter.domain_protection_to_stix(findings))
        assert "domain-name" in types
        assert "indicator" in types
        assert "ipv4-addr" in types
        # indicator->domain (based-on) and domain->ip (resolves-to)
        assert types.count("relationship") == 2

    def test_risk_score_clamped_and_defaulted(self, converter):
        findings = [
            {"id": "D2", "domain": "a.example", "risk_score": 150},
            {"id": "D3", "domain": "b.example", "risk_score": 0},
        ]
        objects = converter.domain_protection_to_stix(findings)
        domains = [o for o in objects if o.type == "domain-name"]
        scores = {d.value: d.x_opencti_score for d in domains}
        assert scores["a.example"] == 100
        assert scores["b.example"] == 50

    def test_ip_only_no_domain(self, converter):
        findings = [{"id": "D4", "ip_address": "8.8.4.4"}]
        types = _types(converter.domain_protection_to_stix(findings))
        assert "ipv4-addr" in types
        assert "domain-name" not in types
        assert "relationship" not in types

    def test_invalid_ip_skipped(self, converter):
        findings = [{"id": "D5", "domain": "c.example", "ip_address": "not-an-ip"}]
        types = _types(converter.domain_protection_to_stix(findings))
        assert "ipv4-addr" not in types
