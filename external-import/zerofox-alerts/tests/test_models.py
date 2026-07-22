"""Tests for ZeroFox Alerts Pydantic models."""

import json

import pytest
from zerofox_alerts.models import ZerofoxAlert


class TestZerofoxAlert:
    """Tests for the ZerofoxAlert model."""

    def test_minimal_alert_parsing(self, minimal_alert_data):
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        assert alert.id == 12345
        assert alert.alert_type == "search_query"
        assert alert.escalated is False
        assert alert.tags == []

    def test_full_alert_parsing(self, full_alert_data):
        alert = ZerofoxAlert.model_validate(full_alert_data)
        assert alert.id == 99999
        assert alert.alert_type == "phishing"
        assert alert.escalated is True
        assert alert.tags == ["phishing", "credential_theft"]
        assert alert.entity.name == "Filigran Corp"
        assert alert.perpetrator.name == "evil_actor"
        assert len(alert.logs) == 2

    def test_metadata_string_parsing(self, minimal_alert_data):
        """metadata field may arrive as stringified JSON."""
        meta = {"justification": "malware", "occurrences": [{"term": "bad.com"}]}
        minimal_alert_data["metadata"] = json.dumps(meta)
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        assert alert.metadata is not None
        assert alert.metadata.justification == "malware"
        assert alert.observable_domains == ["bad.com"]

    def test_metadata_invalid_string(self, minimal_alert_data):
        """Invalid JSON string should result in None metadata."""
        minimal_alert_data["metadata"] = "not-valid-json{{"
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        assert alert.metadata is None

    def test_metadata_none(self, minimal_alert_data):
        """None metadata stays None."""
        minimal_alert_data["metadata"] = None
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        assert alert.metadata is None

    def test_metadata_dict_passthrough(self, minimal_alert_data):
        """Dict metadata is used directly."""
        minimal_alert_data["metadata"] = {"justification": "impersonation"}
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        assert alert.metadata.justification == "impersonation"

    def test_extra_fields_allowed(self, minimal_alert_data):
        """Extra fields from the API should not cause validation errors."""
        minimal_alert_data["unknown_field"] = "should not fail"
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        assert alert.id == 12345


class TestVictimEntity:
    """Tests for the victim_entity property."""

    def test_entity_preferred_over_asset(self):
        alert = ZerofoxAlert.model_validate(
            {
                "id": 1,
                "entity": {"id": 10, "name": "Entity"},
                "asset": {"id": 20, "name": "Asset"},
            }
        )
        assert alert.victim_entity.name == "Entity"

    def test_asset_fallback(self):
        alert = ZerofoxAlert.model_validate(
            {"id": 1, "entity": None, "asset": {"id": 20, "name": "Asset"}}
        )
        assert alert.victim_entity.name == "Asset"

    def test_no_victim(self):
        alert = ZerofoxAlert.model_validate({"id": 1})
        assert alert.victim_entity is None


class TestEffectiveSeverity:
    """Tests for severity mapping logic."""

    @pytest.mark.parametrize(
        "severity,escalated,expected",
        [
            (1, False, "low"),
            (2, False, "medium"),
            (3, False, "high"),
            (4, False, "critical"),
            (None, False, "low"),
            (1, True, "critical"),
            (2, True, "critical"),
            (99, False, "low"),  # unknown severity defaults to low
        ],
    )
    def test_severity_mapping(self, severity, escalated, expected):
        alert = ZerofoxAlert.model_validate(
            {"id": 1, "severity": severity, "escalated": escalated}
        )
        assert alert.effective_severity == expected


class TestExternalUrl:
    """Tests for external_url property."""

    def test_url_construction(self):
        alert = ZerofoxAlert.model_validate({"id": 42})
        assert alert.external_url == "https://cloud.zerofox.com/alerts/42"


class TestDescription:
    """Tests for the rich description property."""

    def test_empty_when_no_notes_or_metadata(self):
        alert = ZerofoxAlert.model_validate({"id": 1})
        assert alert.description == ""

    def test_notes_only(self):
        alert = ZerofoxAlert.model_validate({"id": 1, "notes": "Some notes"})
        assert alert.description == "Some notes"

    def test_metadata_reasons_and_details(self):
        alert = ZerofoxAlert.model_validate(
            {
                "id": 1,
                "metadata": {
                    "alert_reasons": [
                        {"value": {"text_content": "Reason one"}},
                        {"value": "not a dict"},  # should be skipped
                    ],
                    "content_raw_data": {"details": "Some detail"},
                },
            }
        )
        assert "**Alert reason:** Reason one" in alert.description
        assert "**Details:** Some detail" in alert.description

    def test_notes_combined_with_metadata(self):
        alert = ZerofoxAlert.model_validate(
            {
                "id": 1,
                "notes": "My note",
                "metadata": {
                    "content_raw_data": {"details": "Extra info"},
                },
            }
        )
        assert "My note" in alert.description
        assert "**Details:** Extra info" in alert.description


class TestObservableDomains:
    """Tests for observable_domains extraction."""

    def test_extracts_terms(self):
        alert = ZerofoxAlert.model_validate(
            {
                "id": 1,
                "metadata": {
                    "occurrences": [
                        {"term": "evil.com"},
                        {"term": "bad.org"},
                        {"other": "no term"},
                    ]
                },
            }
        )
        assert alert.observable_domains == ["evil.com", "bad.org"]

    def test_no_metadata(self):
        alert = ZerofoxAlert.model_validate({"id": 1})
        assert alert.observable_domains == []
