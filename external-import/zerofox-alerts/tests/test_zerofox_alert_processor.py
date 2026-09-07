"""Tests for the ZeroFox alert processor (conversion logic)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from connectors_sdk.models import TLPMarking
from connectors_sdk.models.enums import (
    IncidentSeverity,
    IncidentType,
    RelationshipType,
    TLPLevel,
)
from zerofox_alerts.models import ZerofoxAlert
from zerofox_alerts.zerofox_alert_processor import (
    ZerofoxAlertsProcessor,
    _refang_url,
    _to_aware_datetime,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_processor() -> ZerofoxAlertsProcessor:
    """Create a processor instance with mocked internals for conversion tests."""
    proc = ZerofoxAlertsProcessor.__new__(ZerofoxAlertsProcessor)
    proc._marking = TLPMarking(level="amber")
    return proc


def _stix_types(objects: list) -> list[str]:
    """Extract STIX type strings from a list of SDK model objects."""
    return [obj.id.split("--")[0] for obj in objects if hasattr(obj, "id")]


def _find_stix(objects: list, stix_type: str) -> list:
    """Filter objects by STIX type prefix in their id."""
    return [
        obj
        for obj in objects
        if hasattr(obj, "id") and obj.id.startswith(f"{stix_type}--")
    ]


# ---------------------------------------------------------------------------
# _to_aware_datetime
# ---------------------------------------------------------------------------


class TestToAwareDatetime:
    def test_valid_iso_with_offset(self):
        result = _to_aware_datetime("2025-07-05T12:00:00+00:00")
        assert result == datetime(2025, 7, 5, 12, 0, tzinfo=timezone.utc)

    def test_valid_iso_zulu(self):
        result = _to_aware_datetime("2025-07-05T12:00:00Z")
        assert result == datetime(2025, 7, 5, 12, 0, tzinfo=timezone.utc)

    def test_valid_iso_with_nonzero_offset(self):
        result = _to_aware_datetime("2025-07-05T14:00:00+02:00")
        assert result == datetime(2025, 7, 5, 12, 0, tzinfo=timezone.utc)

    def test_none_input(self):
        assert _to_aware_datetime(None) is None

    def test_empty_string(self):
        assert _to_aware_datetime("") is None

    def test_invalid_string(self):
        assert _to_aware_datetime("not-a-date") is None


# ---------------------------------------------------------------------------
# _refang_url
# ---------------------------------------------------------------------------


class TestRefangUrl:
    def test_valid_https(self):
        assert _refang_url("https://example.com/path") == "https://example.com/path"

    def test_valid_http(self):
        assert _refang_url("http://example.com") == "http://example.com/"

    def test_defanged_hxxp(self):
        result = _refang_url("hxxp://evil.com/phish")
        assert result == "http://evil.com/phish"

    def test_defanged_hxxps(self):
        result = _refang_url("hxxps://evil.com/page")
        assert result == "https://evil.com/page"

    def test_ftp_returns_none(self):
        assert _refang_url("ftp://not-http.com") is None

    def test_garbage_returns_none(self):
        assert _refang_url("not a url at all") is None

    def test_empty_string_returns_none(self):
        assert _refang_url("") is None


# ---------------------------------------------------------------------------
# _convert_alert
# ---------------------------------------------------------------------------


class TestConvertAlertMinimal:
    """Tests with a minimal alert (only required fields)."""

    def test_produces_incident_and_author(self, minimal_alert):
        proc = _make_processor()
        objects = proc._convert_alert(minimal_alert)
        types = _stix_types(objects)
        assert "identity" in types  # author
        assert "incident" in types

    def test_incident_name_from_rule_name(self, minimal_alert):
        proc = _make_processor()
        objects = proc._convert_alert(minimal_alert)
        incidents = _find_stix(objects, "incident")
        assert incidents[0].name == "Test Rule"

    def test_incident_fallback_name(self, minimal_alert_data):
        minimal_alert_data["rule_name"] = None
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        proc = _make_processor()
        objects = proc._convert_alert(alert)
        incidents = _find_stix(objects, "incident")
        assert incidents[0].name == "ZeroFox Alert #12345"

    def test_no_relationships_without_entity_or_perpetrator(self, minimal_alert):
        proc = _make_processor()
        objects = proc._convert_alert(minimal_alert)
        rels = _find_stix(objects, "relationship")
        assert len(rels) == 0

    def test_severity_mapping(self, minimal_alert):
        proc = _make_processor()
        objects = proc._convert_alert(minimal_alert)
        incidents = _find_stix(objects, "incident")
        assert incidents[0].severity == IncidentSeverity.MEDIUM  # severity=2

    def test_network_label(self, minimal_alert):
        proc = _make_processor()
        objects = proc._convert_alert(minimal_alert)
        incidents = _find_stix(objects, "incident")
        assert "zerofox:network:twitter" in incidents[0].labels


class TestConvertAlertFull:
    """Tests with a full alert (all optional fields present)."""

    def test_all_object_types_present(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        types = _stix_types(objects)
        assert "incident" in types
        assert "identity" in types
        assert "threat-actor" in types
        assert "url" in types
        assert "text" in types  # darkweb_term
        assert "domain-name" in types
        assert "relationship" in types
        assert "note" in types

    def test_incident_type_mapped(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        incidents = _find_stix(objects, "incident")
        assert incidents[0].incident_type == IncidentType.PHISHING

    def test_escalated_labels(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        incidents = _find_stix(objects, "incident")
        labels = incidents[0].labels
        assert "zerofox:escalated" in labels
        assert "zerofox:justification:phishing" in labels
        assert "phishing" in labels
        assert "credential_theft" in labels

    def test_escalated_forces_critical(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        incidents = _find_stix(objects, "incident")
        assert incidents[0].severity == IncidentSeverity.CRITICAL

    def test_victim_identity_created(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        identities = _find_stix(objects, "identity")
        victim_identities = [
            i for i in identities if getattr(i, "name", None) == "Filigran Corp"
        ]
        assert len(victim_identities) == 1

    def test_targets_relationship(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        rels = _find_stix(objects, "relationship")
        targets_rels = [r for r in rels if r.type == RelationshipType.TARGETS]
        assert len(targets_rels) == 1

    def test_threat_actor_created(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        actors = _find_stix(objects, "threat-actor")
        assert len(actors) == 1
        assert actors[0].name == "evil_actor"
        assert "Evil Actor" in actors[0].aliases

    def test_attributed_to_relationship(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        rels = _find_stix(objects, "relationship")
        attr_rels = [r for r in rels if r.type == RelationshipType.ATTRIBUTED_TO]
        assert len(attr_rels) == 1

    def test_perpetrator_url(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        urls = _find_stix(objects, "url")
        url_values = [u.value for u in urls]
        assert "https://x.com/evil_actor" in url_values

    def test_offending_content_url(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        urls = _find_stix(objects, "url")
        url_values = [u.value for u in urls]
        assert "https://evil.example.com/phish" in url_values

    def test_darkweb_term_as_text(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        texts = _find_stix(objects, "text")
        assert len(texts) == 1
        assert texts[0].value == "leaked credentials for target.com"

    def test_domain_names_from_occurrences(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        domains = _find_stix(objects, "domain-name")
        domain_values = [d.value for d in domains]
        assert "evil.example.com" in domain_values
        assert "phish.net" in domain_values

    def test_notes_from_logs(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        notes = _find_stix(objects, "note")
        assert len(notes) == 2
        contents = [n.content for n in notes]
        assert "[ZeroFox] open" in contents
        assert "[ZeroFox] escalated" in contents

    def test_related_to_relationships_count(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        rels = _find_stix(objects, "relationship")
        related = [r for r in rels if r.type == RelationshipType.RELATED_TO]
        # perpetrator URL + offending URL + darkweb text + 2 domain names = 5
        assert len(related) == 5

    def test_external_reference_on_incident(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        incidents = _find_stix(objects, "incident")
        ext_refs = incidents[0].external_references
        assert any(
            ref.source_name == "ZeroFox" and ref.external_id == "99999"
            for ref in ext_refs
        )

    def test_all_objects_have_marking(self, full_alert):
        proc = _make_processor()
        objects = proc._convert_alert(full_alert)
        for obj in objects:
            stix_type = obj.id.split("--")[0] if hasattr(obj, "id") else ""
            if stix_type in ("relationship", "incident", "threat-actor", "note"):
                assert hasattr(obj, "markings")
                assert len(obj.markings) > 0


class TestConvertAlertEdgeCases:
    """Edge cases for conversion."""

    def test_perpetrator_without_url(self, minimal_alert_data):
        minimal_alert_data["perpetrator"] = {
            "name": "actor",
            "url": None,
        }
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        proc = _make_processor()
        objects = proc._convert_alert(alert)
        urls = _find_stix(objects, "url")
        assert len(urls) == 0

    def test_perpetrator_with_non_http_url(self, minimal_alert_data):
        minimal_alert_data["perpetrator"] = {
            "name": "actor",
            "url": "ftp://not-http.com",
        }
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        proc = _make_processor()
        objects = proc._convert_alert(alert)
        urls = _find_stix(objects, "url")
        assert len(urls) == 0

    def test_perpetrator_same_name_and_display_name(self, minimal_alert_data):
        minimal_alert_data["perpetrator"] = {
            "name": "actor",
            "display_name": "actor",
        }
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        proc = _make_processor()
        objects = proc._convert_alert(alert)
        actors = _find_stix(objects, "threat-actor")
        assert actors[0].aliases is None or len(actors[0].aliases) == 0

    def test_offending_url_non_http_skipped(self, minimal_alert_data):
        minimal_alert_data["offending_content_url"] = "ftp://nope.com"
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        proc = _make_processor()
        objects = proc._convert_alert(alert)
        urls = _find_stix(objects, "url")
        assert len(urls) == 0

    def test_defanged_offending_url_refanged(self, minimal_alert_data):
        minimal_alert_data["offending_content_url"] = "hxxp://evil.com/page"
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        proc = _make_processor()
        objects = proc._convert_alert(alert)
        urls = _find_stix(objects, "url")
        assert len(urls) == 1
        assert urls[0].value == "http://evil.com/page"

    def test_defanged_perpetrator_url_refanged(self, minimal_alert_data):
        minimal_alert_data["perpetrator"] = {
            "name": "actor",
            "url": "hxxps://evil.com/profile",
        }
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        proc = _make_processor()
        objects = proc._convert_alert(alert)
        urls = _find_stix(objects, "url")
        assert len(urls) == 1
        assert urls[0].value == "https://evil.com/profile"

    def test_logs_without_timestamp_skipped(self, minimal_alert_data):
        minimal_alert_data["logs"] = [
            {"action": "open", "timestamp": None},
            {"action": None, "timestamp": "2025-01-01T00:00:00Z"},
        ]
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        proc = _make_processor()
        objects = proc._convert_alert(alert)
        notes = _find_stix(objects, "note")
        assert len(notes) == 0

    def test_victim_entity_without_id(self, minimal_alert_data):
        minimal_alert_data["entity"] = {"name": "No ID Corp"}
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        proc = _make_processor()
        objects = proc._convert_alert(alert)
        identities = _find_stix(objects, "identity")
        victim = [i for i in identities if getattr(i, "name", None) == "No ID Corp"]
        assert len(victim) == 1

    def test_incident_type_unknown_maps_to_none(self, minimal_alert_data):
        minimal_alert_data["alert_type"] = "totally_unknown_type"
        alert = ZerofoxAlert.model_validate(minimal_alert_data)
        proc = _make_processor()
        objects = proc._convert_alert(alert)
        incidents = _find_stix(objects, "incident")
        assert incidents[0].incident_type is None


class TestTransform:
    """Tests for the transform generator."""

    def test_transform_yields_deduplicated_objects(self, full_alert_data):
        proc = _make_processor()
        proc.logger = MagicMock()

        # Simulate two identical alerts on the same page → dedup
        page = [full_alert_data, full_alert_data]

        def gen():
            yield page

        results = list(proc.transform(gen()))
        assert len(results) == 1
        # Should have fewer objects than 2x because of deduplication
        all_ids = [getattr(obj, "id", None) for obj in results[0]]
        unique_ids = [i for i in all_ids if i]
        assert len(unique_ids) == len(set(unique_ids))

    def test_transform_skips_invalid_alerts(self, minimal_alert_data):
        proc = _make_processor()
        proc.logger = MagicMock()

        # First alert invalid (missing id), second valid
        page = [{"no_id_field": True}, minimal_alert_data]

        def gen():
            yield page

        results = list(proc.transform(gen()))
        assert len(results) == 1
        proc.logger.error.assert_called()

    def test_transform_empty_page_yields_nothing(self):
        proc = _make_processor()
        proc.logger = MagicMock()

        def gen():
            yield []

        results = list(proc.transform(gen()))
        assert len(results) == 0

    def test_transform_convert_alert_exception_logged(self, minimal_alert_data):
        """When _convert_alert raises, the error is logged and processing continues."""
        proc = _make_processor()
        proc.logger = MagicMock()

        with patch.object(proc, "_convert_alert", side_effect=RuntimeError("boom")):
            page = [minimal_alert_data]

            def gen():
                yield page

            results = list(proc.transform(gen()))
            assert len(results) == 0
            proc.logger.error.assert_called()


class TestPostInit:
    """Tests for post_init method."""

    def test_post_init_sets_client_and_marking(self):
        proc = ZerofoxAlertsProcessor.__new__(ZerofoxAlertsProcessor)
        proc.settings = MagicMock()
        proc.settings.zerofox_alerts = MagicMock(
            api_base_url="https://api.zerofox.com/",
            api_token=MagicMock(get_secret_value=lambda: "test-token"),
            marking=TLPLevel.AMBER,
        )

        with patch(
            "zerofox_alerts.zerofox_alert_processor.ZerofoxAlertsClient"
        ) as mock_client_cls:
            proc.post_init()

        mock_client_cls.assert_called_once_with(
            base_url="https://api.zerofox.com",
            api_token="test-token",
            timeout=60,
            max_retries=3,
            backoff_factor=2.0,
        )
        assert proc._marking.level == "amber"

    def test_post_init_strips_trailing_slash_from_base_url(self):
        proc = ZerofoxAlertsProcessor.__new__(ZerofoxAlertsProcessor)
        proc.settings = MagicMock()
        proc.settings.zerofox_alerts = MagicMock(
            api_base_url="https://api.zerofox.com///",
            api_token=MagicMock(get_secret_value=lambda: "tok"),
            marking=TLPLevel.GREEN,
        )

        with patch(
            "zerofox_alerts.zerofox_alert_processor.ZerofoxAlertsClient"
        ) as mock_client_cls:
            proc.post_init()

        assert mock_client_cls.call_args[1]["base_url"] == "https://api.zerofox.com"


class TestCollect:
    """Tests for collect method."""

    def test_collect_yields_pages_from_client(self):
        proc = _make_processor()
        proc.logger = MagicMock()
        proc.state = MagicMock(last_run=None)
        proc._config = MagicMock(
            import_start_date=timedelta(days=7),
            alert_statuses=["open"],
            page_size=100,
        )
        proc._client = MagicMock()
        page1 = [{"id": 1}]
        page2 = [{"id": 2}, {"id": 3}]
        proc._client.get_alerts.return_value = iter([page1, page2])

        pages = list(proc.collect())
        assert pages == [page1, page2]
        proc._client.get_alerts.assert_called_once()

    def test_collect_sets_work_name(self):
        proc = _make_processor()
        proc.logger = MagicMock()
        proc.state = MagicMock(last_run=datetime(2025, 1, 1, tzinfo=timezone.utc))
        proc._config = MagicMock(
            import_start_date=timedelta(days=7),
            alert_statuses=["open"],
            page_size=100,
        )
        proc._client = MagicMock()
        proc._client.get_alerts.return_value = iter([])

        list(proc.collect())
        assert "2025-01-01" in proc.work_name


class TestGetMinTimestamp:
    """Tests for _get_min_timestamp."""

    def test_uses_last_run_when_available(self):
        proc = _make_processor()
        proc.state = MagicMock(
            last_run=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        )
        result = proc._get_min_timestamp()
        assert result == "2025-06-15T12:00:00Z"

    def test_falls_back_to_import_start_date(self):
        proc = _make_processor()
        proc.state = MagicMock(last_run=None)
        proc._config = MagicMock(import_start_date=timedelta(days=30))

        result = proc._get_min_timestamp()
        # Should be roughly 30 days ago
        parsed = datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        diff = datetime.now(timezone.utc) - parsed
        assert 29 <= diff.days <= 30
