"""Tests for utility functions."""

from connector.utils import lookup_MDM_value, map_attack_score_to_level, sanitize_email


class TestSanitizeEmail:
    """Test email sanitization."""

    def test_removes_bom(self):
        assert sanitize_email("\ufeffuser@example.com") == "user@example.com"

    def test_removes_trailing_bom(self):
        assert sanitize_email("user@example.com\ufeff") == "user@example.com"

    def test_strips_whitespace(self):
        assert sanitize_email("  user@example.com  ") == "user@example.com"

    def test_none_returns_none(self):
        assert sanitize_email(None) is None

    def test_empty_string_returns_empty(self):
        assert sanitize_email("") == ""

    def test_normal_email_unchanged(self):
        assert sanitize_email("test@company.com") == "test@company.com"


class TestMapAttackScoreToLevel:
    """Test attack score to priority/severity mapping."""

    def test_malicious_priority(self):
        assert map_attack_score_to_level(True, True, "malicious", "priority") == "P1"

    def test_malicious_severity(self):
        assert map_attack_score_to_level(True, True, "malicious", "severity") == "high"

    def test_suspicious_priority(self):
        assert map_attack_score_to_level(True, True, "suspicious", "priority") == "P2"

    def test_suspicious_severity(self):
        assert (
            map_attack_score_to_level(True, True, "suspicious", "severity") == "medium"
        )

    def test_spam_priority(self):
        assert map_attack_score_to_level(True, True, "spam", "priority") == "P3"

    def test_spam_severity(self):
        assert map_attack_score_to_level(True, True, "spam", "severity") == "low"

    def test_unknown_verdict_defaults(self):
        assert map_attack_score_to_level(True, True, "unknown", "priority") == "P4"
        assert map_attack_score_to_level(True, True, "unknown", "severity") == "low"

    def test_none_verdict_treated_as_unknown(self):
        assert map_attack_score_to_level(True, True, None, "priority") == "P4"
        assert map_attack_score_to_level(True, True, None, "severity") == "low"

    def test_set_priority_false_returns_none_for_priority(self):
        assert map_attack_score_to_level(False, True, "malicious", "priority") is None

    def test_set_severity_false_returns_none_for_severity(self):
        assert map_attack_score_to_level(True, False, "malicious", "severity") is None

    def test_set_priority_false_still_returns_severity_when_enabled(self):
        assert map_attack_score_to_level(False, True, "malicious", "severity") == "high"

    def test_case_insensitive(self):
        assert map_attack_score_to_level(True, True, "MALICIOUS", "severity") == "high"


class TestLookupMDMValue:
    """Test MDM lookup utility."""

    def test_simple_key(self):
        mdm = {"sender": "test@example.com"}
        assert lookup_MDM_value(mdm, "sender") == "test@example.com"

    def test_nested_key(self):
        mdm = {"sender": {"email": {"email": "phish@evil.com"}}}
        assert lookup_MDM_value(mdm, "sender.email.email") == "phish@evil.com"

    def test_missing_key_returns_none(self):
        mdm = {"sender": {"email": {}}}
        assert lookup_MDM_value(mdm, "sender.email.email") is None

    def test_completely_missing_path_returns_none(self):
        mdm = {}
        assert lookup_MDM_value(mdm, "sender.email.email") is None

    def test_non_dict_intermediate_returns_none(self):
        mdm = {"sender": "not_a_dict"}
        assert lookup_MDM_value(mdm, "sender.email.email") is None

    def test_list_value(self):
        mdm = {"recipients": {"to": [{"email": "a@b.com"}, {"email": "c@d.com"}]}}
        result = lookup_MDM_value(mdm, "recipients.to")
        assert len(result) == 2
        assert result[0]["email"] == "a@b.com"
