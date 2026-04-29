"""RED tests — Incident mapper.

Tests the mapping from a Chronicle RuleAlert (Alert + RuleMetadata) into a
connectors_sdk Incident with correct name, severity, type, description,
labels, and fallback behaviour.

BDD helpers: _given_ / _when_ / _then_ pattern (plain pytest, no pytest-bdd).
"""

import pytest
from connectors_sdk.models.enums import IncidentSeverity
from tests_converter_stix.factories import (
    AlertFactory,
    AlertFieldFactory,
    RuleMetadataFactory,
    RulePropertiesFactory,
    make_author,
    make_risk_score_outcome,
    make_tlp_marking,
)

# --- import under test (will cause ImportError → RED) ---
from google_secops_siem_incidents.mappers.incident_mapper import (  # noqa: E402
    map_incident,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _given_alert_with_fields_and_metadata(
    fields, *, severity="HIGH", rule_type="MULTI_EVENT", tags="", outcomes=None
):
    """Build an Alert + RuleMetadata pair from explicit field/metadata values."""
    alert = AlertFactory.build(
        fields=fields,
        outcomes=outcomes or [],
        rule_type=rule_type,
    )
    rule_metadata = RuleMetadataFactory.build(
        properties=RulePropertiesFactory.build(
            metadata={"severity": severity, "tags": tags},
        ),
    )
    return alert, rule_metadata


def _when_map_incident(alert, rule_metadata):
    """Invoke the incident mapper."""
    return map_incident(
        alert,
        rule_metadata,
        author=make_author(),
        tlp_marking=make_tlp_marking(),
    )


# ---------------------------------------------------------------------------
# Tests — name derivation from alert fields
# ---------------------------------------------------------------------------
class TestIncidentName:
    def test_then_name_from_ip_and_hostname_fields(self):
        """Given fields ip+hostname → name = 'ip:185.100.87.136, hostname:srv01'."""
        # _given_
        fields = [
            AlertFieldFactory.build(name="ip", string_val="185.100.87.136"),
            AlertFieldFactory.build(name="hostname", string_val="srv01"),
        ]
        alert, meta = _given_alert_with_fields_and_metadata(fields)

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_
        assert incident.name == "ip:185.100.87.136, hostname:srv01"

    def test_then_name_falls_back_to_rule_id_when_fields_empty(self):
        """Given empty fields[] → name falls back to rule_id."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([])

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_ — must use rule_id, not crash
        assert meta.rule_id in incident.name

    def test_then_name_falls_back_to_unnamed_when_no_rule_id(self):
        """Given empty fields and minimal metadata → name includes 'unnamed' or rule_id."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([])

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_ — must not be empty
        assert incident.name  # truthy, non-empty string


# ---------------------------------------------------------------------------
# Tests — severity mapping
# ---------------------------------------------------------------------------
class TestIncidentSeverity:
    def test_then_high_severity_maps_correctly(self):
        """Given severity 'HIGH' → IncidentSeverity.HIGH (value = 'high')."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], severity="HIGH")

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_
        assert incident.severity == IncidentSeverity.HIGH

    @pytest.mark.parametrize(
        ("source_severity", "expected"),
        [
            ("LOW", IncidentSeverity.LOW),
            ("MEDIUM", IncidentSeverity.MEDIUM),
            ("HIGH", IncidentSeverity.HIGH),
            ("CRITICAL", IncidentSeverity.CRITICAL),
        ],
    )
    def test_then_severity_enum_parametrized(self, source_severity, expected):
        """Given severity '<source>' → IncidentSeverity.<expected>."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata(
            [], severity=source_severity
        )

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_
        assert incident.severity == expected


# ---------------------------------------------------------------------------
# Tests — type mapping
# ---------------------------------------------------------------------------
class TestIncidentType:
    @pytest.mark.parametrize(
        ("source_type", "expected_value"),
        [
            ("SINGLE_EVENT", "single-event"),
            ("MULTI_EVENT", "multi-event"),
        ],
    )
    def test_then_type_enum_parametrized(self, source_type, expected_value):
        """Given type '<source>' → incident type with value '<expected>'."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], rule_type=source_type)

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_
        assert incident.incident_type == expected_value


# ---------------------------------------------------------------------------
# Tests — description from risk score
# ---------------------------------------------------------------------------
class TestIncidentDescription:
    def test_then_description_is_markdown_table_with_risk_row(self):
        """Given risk_score=75 → description is a markdown table with risk row."""
        # _given_
        outcomes = [make_risk_score_outcome("75")]
        alert, meta = _given_alert_with_fields_and_metadata([], outcomes=outcomes)

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_
        desc = incident.description or ""
        assert "| Panel | Status |" in desc
        assert "| --- | --- |" in desc
        assert "| Risk | 75 |" in desc

    def test_then_description_includes_metadata_rows_from_rule(self):
        """Given metadata with description/priority → rows appear in the table."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata(
            [],
            severity="HIGH",
            rule_type="MULTI_EVENT",
        )
        # Inject metadata fields into the existing properties dict
        meta.properties.metadata["description"] = "Lateral Movement"
        meta.properties.metadata["priority"] = "P1"

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_
        desc = incident.description or ""
        assert "| Category | Lateral Movement |" in desc
        assert "| Priority | P1 |" in desc

    def test_then_description_is_none_when_no_metadata_and_no_risk(self):
        """Given empty metadata and no risk outcome → description is None."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], outcomes=[])

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_
        assert incident.description is None


# ---------------------------------------------------------------------------
# Tests — labels from tags
# ---------------------------------------------------------------------------
class TestIncidentLabels:
    def test_then_tags_become_stripped_labels(self):
        """Given tags 'phishing,malware' → labels = ['phishing', 'malware']."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], tags="phishing,malware")

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_
        assert incident.labels == ["phishing", "malware"]

    def test_then_tags_with_whitespace_are_stripped(self):
        """Given tags ' phishing , malware ' → labels stripped."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata(
            [], tags=" phishing , malware "
        )

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_
        assert incident.labels == ["phishing", "malware"]


# ---------------------------------------------------------------------------
# Tests — last_seen from time_window.end_time
# ---------------------------------------------------------------------------
class TestIncidentLastSeen:
    def test_then_last_seen_set_from_time_window_end_time(self):
        """Given alert.time_window.end_time → incident.last_seen is set."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([])

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_
        assert incident.last_seen is not None
        assert incident.last_seen.tzinfo is not None  # timezone-aware
        assert incident.last_seen.year == 2025  # matches factory default end_time

    def test_then_last_seen_after_first_seen(self):
        """last_seen (time_window end) is after first_seen (detection_timestamp)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([])

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_
        assert incident.first_seen is not None
        assert incident.last_seen is not None
        assert incident.last_seen >= incident.first_seen
