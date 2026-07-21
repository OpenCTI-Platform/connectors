"""Tests for the STIX converter."""

from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import ConverterToStix
from pycti import Indicator, Malware, StixCoreRelationship


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

    def test_stable_fallback_id_is_deterministic(self, converter):
        first = converter._stable_fallback_id("malware", "RedLine", "1.2.3.4")
        second = converter._stable_fallback_id("malware", "RedLine", "1.2.3.4")
        assert first == second
        assert first.startswith("cbs-malware-")

    def test_stable_fallback_id_varies_with_content(self, converter):
        a = converter._stable_fallback_id("breach", "a@example.com")
        b = converter._stable_fallback_id("breach", "b@example.com")
        assert a != b

    def test_stable_fallback_id_ignores_empty_fields(self, converter):
        # Empty/falsy fields are skipped, so no content collapses to the prefix.
        assert converter._stable_fallback_id(
            "cardleak", "", None
        ) == converter._stable_fallback_id("cardleak")


class TestDeterministicFallbackIds:
    """Records without an API id must yield stable STIX ids across runs."""

    def _malware_ext_id(self, objects):
        malware = [o for o in objects if o.type == "malware"]
        return malware[0].external_references[0].external_id

    def test_malware_external_id_is_family_stable(self, converter):
        # The Malware SDO is de-duplicated per family, so its external
        # reference is family-stable (malware:<family>) rather than a
        # per-record id — identical across logs and across runs.
        log = {"malware_family": "RedLine", "ip": "1.2.3.4"}
        first = self._malware_ext_id(converter.malware_logs_to_stix([dict(log)]))
        second = self._malware_ext_id(converter.malware_logs_to_stix([dict(log)]))
        assert first == second
        assert first == "malware:RedLine"

    def test_breached_credential_without_id_is_stable(self, converter):
        cred = {"email": "jdoe@example.com", "username": "jdoe"}

        def ids(objects):
            return {o.id for o in objects if o.type in ("note", "indicator")}

        first = ids(converter.breached_credentials_to_stix([dict(cred)]))
        second = ids(converter.breached_credentials_to_stix([dict(cred)]))
        assert first == second

    def test_card_leak_without_id_is_stable(self, converter):
        card = {"bank_name": "ACME Bank", "date": "2026-03-04T18:00:00Z"}

        def note_id(objects):
            return next(o.id for o in objects if o.type == "note")

        assert note_id(converter.card_leaks_to_stix([dict(card)])) == note_id(
            converter.card_leaks_to_stix([dict(card)])
        )

    def test_domain_protection_without_id_is_stable(self, converter):
        finding = {"domain": "bad.example", "type": "typosquatting"}

        def indicator_id(objects):
            return next(o.id for o in objects if o.type == "indicator")

        assert indicator_id(
            converter.domain_protection_to_stix([dict(finding)])
        ) == indicator_id(converter.domain_protection_to_stix([dict(finding)]))


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


class TestObservableAuthorAttribution:
    """SCOs must carry x_opencti_created_by_ref so OpenCTI attributes them."""

    def _observables(self, objects):
        sco_types = {"ipv4-addr", "domain-name", "email-addr", "user-account"}
        return [o for o in objects if o.type in sco_types]

    def test_malware_log_observables_attributed(self, converter):
        objects = converter.malware_logs_to_stix(
            [
                {
                    "id": "M1",
                    "malware_family": "RedLine",
                    "ip": "1.2.3.4",
                    "domain": "evil.example",
                    "email": "victim@example.com",
                }
            ]
        )
        observables = self._observables(objects)
        assert observables
        for obs in observables:
            assert obs.x_opencti_created_by_ref == converter.author.id

    def test_breached_credential_observables_attributed(self, converter):
        objects = converter.breached_credentials_to_stix(
            [
                {
                    "id": "C1",
                    "email": "jdoe@example.com",
                    "username": "jdoe",
                    "domain": "example.com",
                }
            ]
        )
        observables = self._observables(objects)
        assert {o.type for o in observables} >= {
            "email-addr",
            "domain-name",
            "user-account",
        }
        for obs in observables:
            assert obs.x_opencti_created_by_ref == converter.author.id

    def test_domain_protection_observables_attributed(self, converter):
        objects = converter.domain_protection_to_stix(
            [{"id": "D1", "domain": "bad.example", "ip_address": "8.8.8.8"}]
        )
        observables = self._observables(objects)
        assert {o.type for o in observables} == {"domain-name", "ipv4-addr"}
        for obs in observables:
            assert obs.x_opencti_created_by_ref == converter.author.id


class TestPyctiGeneratedIds:
    """SDO/SRO ids must come from pycti generators for cross-connector dedup."""

    def test_malware_id_uses_pycti_generator(self, converter):
        objects = converter.malware_logs_to_stix(
            [{"id": "M1", "malware_family": "RedLine", "ip": "1.2.3.4"}]
        )
        malware = next(o for o in objects if o.type == "malware")
        assert malware.id == Malware.generate_id("RedLine")

    def test_breached_indicator_id_uses_pycti_generator(self, converter):
        objects = converter.breached_credentials_to_stix(
            [{"id": "C1", "email": "jdoe@example.com"}]
        )
        indicator = next(o for o in objects if o.type == "indicator")
        assert indicator.id == Indicator.generate_id(indicator.pattern)

    def test_domain_indicator_id_uses_pycti_generator(self, converter):
        objects = converter.domain_protection_to_stix(
            [{"id": "D1", "domain": "bad.example"}]
        )
        indicator = next(o for o in objects if o.type == "indicator")
        assert indicator.id == Indicator.generate_id(indicator.pattern)

    def test_relationship_id_uses_pycti_generator(self, converter):
        objects = converter.malware_logs_to_stix(
            [{"id": "M1", "malware_family": "RedLine", "ip": "1.2.3.4"}]
        )
        rel = next(o for o in objects if o.type == "relationship")
        assert rel.id == StixCoreRelationship.generate_id(
            rel.relationship_type, rel.source_ref, rel.target_ref
        )


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

    def test_incident_blank_type_yields_no_empty_label(self, converter):
        # A blank/whitespace type must be normalised to "unknown" rather than
        # leaving an empty label that would trigger add_label(label_name="").
        converter.incidents_to_stix([{"id": "INC-E", "subject": "X", "type": "   "}])
        labels = converter.incident_case_metadata[0]["labels"]
        assert "" not in labels
        assert "unknown" in labels

    def test_incident_punctuation_type_drops_empty_label(self, converter):
        # A type made up solely of punctuation slugifies to "" and must be
        # dropped from the labels rather than emitted as an empty label.
        converter.incidents_to_stix([{"id": "INC-P", "subject": "X", "type": "***"}])
        labels = converter.incident_case_metadata[0]["labels"]
        assert "" not in labels
        assert "ctm360-cbs" in labels

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

    def test_malware_links_all_observed_infrastructure(self, converter):
        # The malware family must be linked (uses) to every observed
        # observable — IP, domain and email — not just the IP.
        logs = [
            {
                "id": "M1",
                "malware_family": "RedLine",
                "ip": "1.2.3.4",
                "domain": "evil.example",
                "email": "victim@example.com",
            }
        ]
        objects = converter.malware_logs_to_stix(logs)
        malware = next(o for o in objects if o.type == "malware")
        rels = [o for o in objects if o.type == "relationship"]
        assert len(rels) == 3
        assert all(r.relationship_type == "uses" for r in rels)
        assert all(r.source_ref == malware.id for r in rels)
        assert {r.target_ref.split("--")[0] for r in rels} == {
            "ipv4-addr",
            "domain-name",
            "email-addr",
        }

    def test_unknown_family_emits_observables_without_relationships(self, converter):
        # Without a known family there is no Malware SDO to anchor the
        # relationships, but the observables are still emitted.
        logs = [
            {
                "id": "M9",
                "malware_family": "Unknown",
                "domain": "x.example",
                "email": "a@b.example",
            }
        ]
        objects = converter.malware_logs_to_stix(logs)
        assert not [o for o in objects if o.type == "relationship"]
        assert {o.type for o in objects if o.type in ("domain-name", "email-addr")} == {
            "domain-name",
            "email-addr",
        }

    def test_same_family_deduplicated(self, converter):
        # Multiple logs sharing a family must yield exactly one Malware SDO
        # (its id is family-derived), but every observable and relationship
        # must still be emitted and point at that single Malware.
        logs = [
            {"id": "M1", "malware_family": "RedLine", "ip": "1.2.3.4"},
            {"id": "M2", "malware_family": "RedLine", "ip": "5.6.7.8"},
        ]
        objects = converter.malware_logs_to_stix(logs)
        malware = [o for o in objects if o.type == "malware"]
        assert len(malware) == 1
        ips = [o for o in objects if o.type == "ipv4-addr"]
        assert {i.value for i in ips} == {"1.2.3.4", "5.6.7.8"}
        rels = [o for o in objects if o.type == "relationship"]
        assert len(rels) == 2
        assert all(r.source_ref == malware[0].id for r in rels)


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

    def test_invalid_email_without_username_uses_nonempty_pattern(self, converter):
        # An email present but invalid (no "@") with no username must not yield
        # an empty user-account pattern (which would collapse unrelated records
        # onto a single constant Indicator id). It falls back to the email value
        # and stays consistent with the UserAccount account_login.
        objects = converter.breached_credentials_to_stix(
            [{"id": "C4", "email": "not-an-email"}]
        )
        indicators = [o for o in objects if o.type == "indicator"]
        assert indicators
        assert indicators[0].pattern == "[user-account:account_login = 'not-an-email']"
        user_accounts = [o for o in objects if o.type == "user-account"]
        assert user_accounts[0].account_login == "not-an-email"

    def test_invalid_email_indicator_ids_are_distinct(self, converter):
        # Two records with different invalid emails (and no username) must map to
        # distinct Indicators rather than collapsing onto one empty-pattern id.
        objects = converter.breached_credentials_to_stix(
            [
                {"id": "C5", "email": "bad-one"},
                {"id": "C6", "email": "bad-two"},
            ]
        )
        indicator_ids = {o.id for o in objects if o.type == "indicator"}
        assert len(indicator_ids) == 2


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
