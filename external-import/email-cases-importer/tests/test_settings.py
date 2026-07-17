"""Unit tests for connector.settings — Pydantic field validators and parsers.

These tests instantiate EmailCasesConfig directly so they don't require the full
ConnectorSettings (which depends on connectors-sdk environment loading).
"""

import json

import pytest
from pydantic import ValidationError

from connector.settings import EmailCasesConfig


def _base_kwargs(**overrides):
    """Minimal valid kwargs for EmailCasesConfig (only required fields)."""
    base = {
        "sender_address": "alerts@example.com",
        "subject_filters": '[{"type":"contains","value":"Alert"}]',
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# subject_filters validator
# ---------------------------------------------------------------------------


class TestSubjectFiltersValidator:
    def test_valid_filters(self):
        cfg = EmailCasesConfig(**_base_kwargs())
        assert cfg.get_parsed_subject_filters() == [
            {"type": "contains", "value": "Alert"}
        ]

    def test_invalid_json_raises(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(**_base_kwargs(subject_filters="not-json"))

    def test_must_be_array(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(**_base_kwargs(subject_filters='{"type":"exact"}'))

    def test_filter_must_have_type_and_value(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(**_base_kwargs(subject_filters='[{"type":"exact"}]'))

    def test_invalid_filter_type(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(
                **_base_kwargs(subject_filters='[{"type":"glob","value":"*"}]')
            )

    @pytest.mark.parametrize("ftype", ["exact", "contains", "regex"])
    def test_all_supported_filter_types(self, ftype):
        cfg = EmailCasesConfig(
            **_base_kwargs(subject_filters=json.dumps([{"type": ftype, "value": "x"}]))
        )
        assert cfg.get_parsed_subject_filters()[0]["type"] == ftype


# ---------------------------------------------------------------------------
# subject_rules validator
# ---------------------------------------------------------------------------


class TestSubjectRulesValidator:
    def test_default_empty_list(self):
        cfg = EmailCasesConfig(**_base_kwargs())
        assert cfg.get_parsed_subject_rules() == []

    def test_valid_rule(self):
        rule = {
            "match_type": "contains",
            "value": "Threat",
            "labels": ["Threat Alert"],
        }
        cfg = EmailCasesConfig(**_base_kwargs(subject_rules=json.dumps([rule])))
        assert cfg.get_parsed_subject_rules() == [rule]

    def test_invalid_match_type(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(
                **_base_kwargs(subject_rules='[{"match_type":"glob","value":"*"}]')
            )

    def test_missing_required_keys(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(**_base_kwargs(subject_rules='[{"match_type":"exact"}]'))

    def test_must_be_array(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(**_base_kwargs(subject_rules="{}"))

    def test_invalid_json(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(**_base_kwargs(subject_rules="not-json"))

    @pytest.mark.parametrize(
        "match_type", ["exact", "contains", "starts_with", "regex"]
    )
    def test_all_supported_match_types(self, match_type):
        cfg = EmailCasesConfig(
            **_base_kwargs(
                subject_rules=json.dumps([{"match_type": match_type, "value": "x"}])
            )
        )
        assert cfg.get_parsed_subject_rules()[0]["match_type"] == match_type


# ---------------------------------------------------------------------------
# sender_rules validator
# ---------------------------------------------------------------------------


class TestSenderRulesValidator:
    def test_default_empty_list(self):
        cfg = EmailCasesConfig(**_base_kwargs())
        assert cfg.get_parsed_sender_rules() == []

    def test_valid_rule(self):
        rule = {"sender": "x@y.com", "author": "Acme"}
        cfg = EmailCasesConfig(**_base_kwargs(sender_rules=json.dumps([rule])))
        assert cfg.get_parsed_sender_rules() == [rule]

    def test_must_be_array(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(**_base_kwargs(sender_rules='{"sender":"x"}'))

    def test_missing_sender_field(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(**_base_kwargs(sender_rules='[{"author":"Acme"}]'))

    def test_invalid_json(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(**_base_kwargs(sender_rules="not-json"))


# ---------------------------------------------------------------------------
# labels parsing
# ---------------------------------------------------------------------------


class TestParsedLabels:
    def test_empty_default(self):
        cfg = EmailCasesConfig(**_base_kwargs())
        assert cfg.get_parsed_labels() == []

    def test_comma_separated(self):
        cfg = EmailCasesConfig(**_base_kwargs(labels="A,B,C"))
        assert cfg.get_parsed_labels() == ["A", "B", "C"]

    def test_strips_whitespace(self):
        cfg = EmailCasesConfig(**_base_kwargs(labels=" A , B , C "))
        assert cfg.get_parsed_labels() == ["A", "B", "C"]

    def test_drops_empty_entries(self):
        cfg = EmailCasesConfig(**_base_kwargs(labels="A,,B,"))
        assert cfg.get_parsed_labels() == ["A", "B"]


# ---------------------------------------------------------------------------
# Defaults / typing
# ---------------------------------------------------------------------------


class TestStartDateValidator:
    def test_empty_default(self):
        cfg = EmailCasesConfig(**_base_kwargs())
        assert cfg.start_date == ""
        assert cfg.get_parsed_start_date() is None

    def test_accepts_date_only(self):
        cfg = EmailCasesConfig(**_base_kwargs(start_date="2026-04-01"))
        parsed = cfg.get_parsed_start_date()
        assert parsed is not None
        assert parsed.year == 2026 and parsed.month == 4 and parsed.day == 1
        # must be tz-aware (UTC)
        assert parsed.tzinfo is not None
        assert parsed.utcoffset().total_seconds() == 0

    def test_accepts_iso_with_z(self):
        cfg = EmailCasesConfig(**_base_kwargs(start_date="2026-04-01T08:30:00Z"))
        parsed = cfg.get_parsed_start_date()
        assert parsed is not None
        assert parsed.hour == 8 and parsed.minute == 30
        assert parsed.tzinfo is not None

    def test_accepts_iso_with_offset(self):
        cfg = EmailCasesConfig(**_base_kwargs(start_date="2026-04-01T08:30:00+02:00"))
        parsed = cfg.get_parsed_start_date()
        assert parsed is not None
        assert parsed.tzinfo is not None

    def test_rejects_garbage(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(**_base_kwargs(start_date="not-a-date"))

    def test_rejects_wrong_format(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(**_base_kwargs(start_date="04/01/2026"))


class TestDefaults:
    def test_protocol_default_is_imap(self):
        cfg = EmailCasesConfig(**_base_kwargs())
        assert cfg.protocol == "imap"

    def test_invalid_protocol_rejected(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(**_base_kwargs(protocol="pop3"))

    def test_invalid_thread_strategy_rejected(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(**_base_kwargs(thread_tracking_strategy="hashing"))

    def test_invalid_ews_auth_rejected(self):
        with pytest.raises(ValidationError):
            EmailCasesConfig(**_base_kwargs(ews_auth_type="Kerberos"))

    def test_password_marker_defaults(self):
        cfg = EmailCasesConfig(**_base_kwargs())
        assert cfg.password_prefix == "---BEGIN PASSWORD---"
        assert cfg.password_suffix == "---END PASSWORD---"
        assert cfg.password_strip_whitespace is False

    def test_import_settings_defaults(self):
        cfg = EmailCasesConfig(**_base_kwargs())
        assert cfg.import_interval == 300
        assert cfg.max_emails_per_cycle == 50
        assert cfg.tls_verify is True
        assert cfg.max_attachment_size_mb == 25
        assert cfg.attachment_store_in_opencti is True
