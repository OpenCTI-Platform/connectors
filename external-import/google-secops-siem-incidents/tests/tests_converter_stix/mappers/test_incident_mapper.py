"""RED tests — Incident mapper.

Tests the mapping from a Chronicle RuleAlert (Alert + RuleMetadata) into a
connectors_sdk Incident with correct name, severity, type, description,
labels, and fallback behaviour.

BDD helpers: _given_ / _when_ / _then_ pattern (plain pytest, no pytest-bdd).
"""

import pytest
from connectors_sdk.models.enums import IncidentSeverity
from google_secops_siem_incidents.mappers.incident_mapper import map_incident
from google_secops_siem_incidents.utils.enums import Priority, Severity
from tests_converter_stix.factories import (
    AlertFactory,
    AlertFieldFactory,
    RuleMetadataFactory,
    RulePropertiesFactory,
    make_author,
    make_risk_score_outcome,
    make_tlp_marking,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _given_alert_with_fields_and_metadata(
    fields,
    *,
    severity="HIGH",
    priority="",
    rule_type="MULTI_EVENT",
    tags="",
    outcomes=None,
):
    """Build an Alert + RuleMetadata pair from explicit field/metadata values."""
    alert = AlertFactory.build(
        fields=fields,
        outcomes=outcomes or [],
        rule_type=rule_type,
    )
    metadata = {"severity": severity, "tags": tags}
    if priority:
        metadata["priority"] = priority
    rule_metadata = RuleMetadataFactory.build(
        properties=RulePropertiesFactory.build(
            name="rule_name",
            metadata=metadata,
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
        assert (
            incident.name == "rule_name:rule_name - ip:185.100.87.136, hostname:srv01"
        )

    def test_then_name_falls_back_to_rule_id_when_fields_empty(self):
        """Given empty fields[] → name falls back to rule_id."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([])

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_ — must use rule_id, not crash
        assert alert.id in incident.name

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
        assert "| Attribute | Value |" in desc
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


# ---------------------------------------------------------------------------
# Tests — external reference from SecOps URL
# ---------------------------------------------------------------------------
class TestIncidentExternalReference:
    def test_then_external_reference_created_when_secops_url_provided(self):
        """Given a secops_base_url → incident has an external reference with correct URL."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([])
        secops_url = "https://acme.backstory.chronicle.security"

        # _when_
        incident = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            secops_base_url=secops_url,
        )

        # _then_
        assert incident.external_references is not None
        assert len(incident.external_references) == 1
        ext_ref = incident.external_references[0]
        assert ext_ref.source_name == "Google SecOps SIEM"
        assert ext_ref.url == f"{secops_url}/alerts/{alert.id}"
        assert ext_ref.external_id == alert.id

    def test_then_external_reference_strips_trailing_slash(self):
        """Given a secops_base_url with trailing slash → URL has no double slash."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([])
        secops_url = "https://acme.backstory.chronicle.security/"

        # _when_
        incident = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            secops_base_url=secops_url,
        )

        # _then_
        ext_ref = incident.external_references[0]
        assert "//" not in ext_ref.url.replace("https://", "")

    def test_then_no_external_reference_when_secops_url_is_none(self):
        """Given no secops_base_url → incident has no external references."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([])

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_
        assert incident.external_references is None

    def test_then_external_reference_converts_to_stix2(self):
        """Given a secops_base_url → the incident's STIX2 object includes the external reference."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([])
        secops_url = "https://acme.backstory.chronicle.security"

        # _when_
        incident = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            secops_base_url=secops_url,
        )
        stix_obj = incident.to_stix2_object()

        # _then_
        assert hasattr(stix_obj, "external_references")
        assert len(stix_obj.external_references) == 1
        assert (
            stix_obj.external_references[0]["url"] == f"{secops_url}/alerts/{alert.id}"
        )


# ---------------------------------------------------------------------------
# Tests — severity filter (threshold-based)
# ---------------------------------------------------------------------------
class TestSeverityFilter:
    def test_then_returns_none_when_below_threshold(self):
        """Given severity 'LOW' and threshold 'high' → None (filtered out)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], severity="LOW")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            severity_filter=Severity.HIGH,
        )

        # _then_
        assert result is None

    def test_then_returns_incident_when_at_threshold(self):
        """Given severity 'HIGH' and threshold 'high' → incident returned."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], severity="HIGH")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            severity_filter=Severity.HIGH,
        )

        # _then_
        assert result is not None

    def test_then_returns_incident_when_above_threshold(self):
        """Given severity 'CRITICAL' and threshold 'high' → incident returned."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], severity="CRITICAL")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            severity_filter=Severity.HIGH,
        )

        # _then_
        assert result is not None

    def test_then_returns_incident_when_no_threshold(self):
        """Given any severity and empty threshold → incident returned (no filter)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], severity="INFO")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            severity_filter=None,
        )

        # _then_
        assert result is not None

    def test_then_returns_incident_when_unknown_severity(self):
        """Given unknown severity and a threshold → incident returned (unknown passes)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], severity="CUSTOM_LEVEL")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            severity_filter=Severity.HIGH,
        )

        # _then_
        assert result is not None

    def test_then_returns_incident_when_empty_severity(self):
        """Given empty severity and a threshold → incident returned (no severity = pass)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], severity="")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            severity_filter=Severity.HIGH,
        )

        # _then_
        assert result is not None


# ---------------------------------------------------------------------------
# Tests — priority filter (threshold-based)
# ---------------------------------------------------------------------------
class TestPriorityFilter:
    def test_then_returns_none_when_below_threshold(self):
        """Given priority 'LOW' and threshold HIGH → None (filtered out)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], priority="LOW")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            priority_filter=Priority.HIGH,
        )

        # _then_
        assert result is None

    def test_then_returns_incident_when_at_threshold(self):
        """Given priority 'HIGH' and threshold HIGH → incident returned."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], priority="HIGH")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            priority_filter=Priority.HIGH,
        )

        # _then_
        assert result is not None

    def test_then_returns_incident_when_above_threshold(self):
        """Given priority 'CRITICAL' and threshold HIGH → incident returned."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], priority="CRITICAL")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            priority_filter=Priority.HIGH,
        )

        # _then_
        assert result is not None

    def test_then_returns_incident_when_no_threshold(self):
        """Given any priority and None threshold → incident returned."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], priority="INFO")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            priority_filter=None,
        )

        # _then_
        assert result is not None

    def test_then_returns_incident_when_unknown_priority(self):
        """Given unknown priority and a threshold → incident returned (unknown passes)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], priority="P1")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            priority_filter=Priority.HIGH,
        )

        # _then_
        assert result is not None

    def test_then_returns_incident_when_empty_priority(self):
        """Given empty priority and a threshold → incident returned (no priority = pass)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], priority="")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            priority_filter=Priority.HIGH,
        )

        # _then_
        assert result is not None


# ---------------------------------------------------------------------------
# Tests — risk score filter (threshold-based)
# ---------------------------------------------------------------------------
class TestRiskScoreFilter:
    def test_then_returns_none_when_below_threshold(self):
        """Given risk_score=50 and threshold 80 → None (filtered out)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata(
            [], outcomes=[make_risk_score_outcome("50")]
        )

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            risk_score_filter=80,
        )

        # _then_
        assert result is None

    def test_then_returns_incident_when_at_threshold(self):
        """Given risk_score=80 and threshold 80 → incident returned."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata(
            [], outcomes=[make_risk_score_outcome("80")]
        )

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            risk_score_filter=80,
        )

        # _then_
        assert result is not None

    def test_then_returns_incident_when_above_threshold(self):
        """Given risk_score=95 and threshold 80 → incident returned."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata(
            [], outcomes=[make_risk_score_outcome("95")]
        )

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            risk_score_filter=80,
        )

        # _then_
        assert result is not None

    def test_then_returns_incident_when_no_threshold(self):
        """Given any risk_score and None threshold → incident returned."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata(
            [], outcomes=[make_risk_score_outcome("10")]
        )

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            risk_score_filter=None,
        )

        # _then_
        assert result is not None

    def test_then_returns_incident_when_no_risk_score_outcome(self):
        """Given no risk_score outcome and a threshold → incident returned (no score = pass)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], outcomes=[])

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            risk_score_filter=80,
        )

        # _then_
        assert result is not None


# ---------------------------------------------------------------------------
# Tests — tags filter (include/exclude)
# ---------------------------------------------------------------------------
class TestTagsFilter:
    def test_then_returns_incident_when_tag_in_include_list(self):
        """Given tags 'phishing,malware' and include=['phishing'] → incident returned."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], tags="phishing,malware")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            tags_include=["phishing"],
        )

        # _then_
        assert result is not None

    def test_then_returns_none_when_no_tag_in_include_list(self):
        """Given tags 'test' and include=['phishing'] → None (filtered out)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], tags="test")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            tags_include=["phishing"],
        )

        # _then_
        assert result is None

    def test_then_returns_none_when_tag_in_exclude_list(self):
        """Given tags 'phishing,malware' and exclude=['malware'] → None (filtered out)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], tags="phishing,malware")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            tags_exclude=["malware"],
        )

        # _then_
        assert result is None

    def test_then_returns_incident_when_no_tag_in_exclude_list(self):
        """Given tags 'test' and exclude=['malware'] → incident returned."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], tags="test")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            tags_exclude=["malware"],
        )

        # _then_
        assert result is not None

    def test_then_returns_none_when_no_tags_and_include_set(self):
        """Given empty tags and include=['phishing'] → None (no tags to match)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], tags="")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            tags_include=["phishing"],
        )

        # _then_
        assert result is None

    def test_then_returns_incident_when_no_tags_and_exclude_set(self):
        """Given empty tags and exclude=['malware'] → incident returned (nothing to exclude)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], tags="")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            tags_exclude=["malware"],
        )

        # _then_
        assert result is not None

    def test_then_case_insensitive_matching(self):
        """Given tags 'Phishing' and include=['phishing'] → incident returned."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], tags="Phishing")

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            tags_include=["phishing"],
        )

        # _then_
        assert result is not None


# ---------------------------------------------------------------------------
# Tests — edge cases
# ---------------------------------------------------------------------------
class TestIncidentEdgeCases:
    def test_then_non_numeric_risk_score_passes_filter(self):
        """Given a non-numeric risk_score and a threshold → incident returned (ValueError caught)."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata(
            [], outcomes=[make_risk_score_outcome("not_a_number")]
        )

        # _when_
        result = map_incident(
            alert,
            meta,
            author=make_author(),
            tlp_marking=make_tlp_marking(),
            risk_score_filter=80,
        )

        # _then_
        assert result is not None

    def test_then_description_includes_mitre_url(self):
        """Given metadata with mitre_attach_url → row appears in description table."""
        # _given_
        alert, meta = _given_alert_with_fields_and_metadata([], severity="HIGH")
        meta.properties.metadata["mitre_attach_url"] = "https://attack.mitre.org/T1234"

        # _when_
        incident = _when_map_incident(alert, meta)

        # _then_
        desc = incident.description or ""
        assert "| Title | https://attack.mitre.org/T1234 |" in desc
