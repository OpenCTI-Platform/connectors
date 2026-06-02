"""Tests for the HackerView STIX converter."""

from unittest.mock import MagicMock

import pytest
import stix2
from connector.converter_to_stix import ConverterToStix


@pytest.fixture
def converter():
    return ConverterToStix(helper=MagicMock())


def _types(objects):
    return [obj.type for obj in objects]


def _full_issue(**overrides):
    issue = {
        "ticket_id": "HV-1",
        "issue_name": "Exposed admin panel",
        "severity": "high",
        "cve_id": "CVE-2024-12345",
        "cwe": [{"cwe_id": "CWE-79", "cwe_detail": "XSS"}],
        "issue_category": "misconfiguration",
        "issue_type": "exposure",
        "status": "open",
        "progress_status": "in_progress",
        "host": "admin.example.com",
        "domain": "example.com",
        "resolved_ip": "1.2.3.4",
        "technologies": ["nginx", "php"],
        "environments": ["prod"],
        "hackerview_link": "https://hackerview.ctm360.com/issue/HV-1",
        "first_seen": "2026-03-04T18:00:00Z",
        "last_updated": "2026-03-05T10:00:00Z",
        "brand": "ACME",
        "discovery_source": "scan",
    }
    issue.update(overrides)
    return issue


class TestHelpers:
    def test_severity_to_score(self, converter):
        assert converter._severity_to_score("critical") == 95
        assert converter._severity_to_score("nope") == 50

    def test_severity_to_priority(self, converter):
        assert converter._severity_to_priority("high") == "P2"
        assert converter._severity_to_priority("nope") == "P3"

    def test_normalize_severity(self, converter):
        assert converter._normalize_severity("info") == "low"
        assert converter._normalize_severity("weird") == "medium"

    def test_slugify_label(self, converter):
        assert converter._slugify_label("Open Port!") == "open-port"

    def test_flatten_issue_promotes_meta(self, converter):
        flat = converter._flatten_issue(
            {"ticket_id": "T1", "meta": {"domain": "x.com", "ticket_id": "T2"}}
        )
        assert flat["domain"] == "x.com"
        assert flat["ticket_id"] == "T1"  # top-level wins

    def test_format_list_field_cwe(self, converter):
        out = converter._format_list_field([{"cwe_id": "CWE-79", "cwe_detail": "XSS"}])
        assert out == "CWE-79 (XSS)"

    def test_first_list_item(self, converter):
        assert converter._first_list_item(["a", "b"]) == "a"
        assert converter._first_list_item("x") == "x"
        assert converter._first_list_item([]) == ""

    def test_ext_ref_with_url(self, converter):
        ref = converter._ext_ref("CTM360-HackerView", "1", url="https://e.x")
        assert ref.url == "https://e.x"


class TestIssuesToStix:
    def test_full_issue_produces_all_objects_without_error(self, converter):
        objects = converter.issues_to_stix([_full_issue()])
        types = _types(objects)
        assert "identity" in types  # author + system
        assert "vulnerability" in types
        assert "note" in types
        assert "attack-pattern" in types
        assert "software" in types
        assert "relationship" in types
        assert "case-incident" in types  # shipped in the bundle, not via API
        assert len(converter.issue_case_metadata) == 1

    def test_technologies_relationship_has_relationship_type(self, converter):
        # Regression: the System->Software relationship previously omitted
        # relationship_type and crashed stix2 validation.
        objects = converter.issues_to_stix([_full_issue()])
        rels = [o for o in objects if o.type == "relationship"]
        software_rels = [r for r in rels if str(r.target_ref).startswith("software--")]
        assert software_rels
        assert all(r.relationship_type == "related-to" for r in software_rels)

    def test_software_id_is_deterministic(self, converter):
        first = converter.issues_to_stix([_full_issue(ticket_id="A")])
        second = converter.issues_to_stix([_full_issue(ticket_id="B")])
        sw1 = sorted(o.id for o in first if o.type == "software")
        sw2 = sorted(o.id for o in second if o.type == "software")
        assert sw1 == sw2  # same technologies -> same Software ids

    def test_issue_without_ticket_id_skipped(self, converter):
        objects = converter.issues_to_stix([{"issue_name": "no id"}])
        assert _types(objects) == ["identity"]
        assert converter.issue_case_metadata == []
        converter.helper.connector_logger.warning.assert_called_once()

    def test_issue_without_cve_has_no_vulnerability(self, converter):
        objects = converter.issues_to_stix([_full_issue(cve_id="", cwe=[])])
        assert "vulnerability" not in _types(objects)

    def test_case_incident_object_built_in_bundle(self, converter):
        objects = converter.issues_to_stix([_full_issue()])
        cases = [o for o in objects if o.type == "case-incident"]
        assert len(cases) == 1
        case = cases[0]
        assert case.id.startswith("case-incident--")
        assert case.severity == "high"
        assert case.priority == "P2"
        assert case.response_types == ["exposure"]
        assert "ctm360-hackerview" in case.labels
        # The status label uses the combined status+progress form so it matches
        # the value the tracker maintains (see test below).
        assert "status:open:in_progress" in case.labels
        assert case.created_by_ref == converter.author.id
        assert any(ref.external_id == "HV-1" for ref in case.external_references)
        # The case references the objects built for the issue (note is always one).
        assert case.object_refs

    def test_case_label_matches_tracker_seed(self, converter):
        # The `status:` label shipped on the case must equal `status:` + the
        # initial_status seeded into the tracker, otherwise the tracker would
        # remove a non-existent label and leak the original on the first change.
        objects = converter.issues_to_stix([_full_issue()])
        case = next(o for o in objects if o.type == "case-incident")
        meta = converter.issue_case_metadata[0]
        status_labels = [label for label in case.labels if label.startswith("status:")]
        assert status_labels == [f"status:{meta['initial_status']}"]
        # The old split form (a separate `progress:` label) must not be emitted.
        assert not any(label.startswith("progress:") for label in case.labels)

    def test_case_label_bare_status_when_no_progress(self, converter):
        objects = converter.issues_to_stix([_full_issue(progress_status="")])
        case = next(o for o in objects if o.type == "case-incident")
        assert "status:open" in case.labels
        assert converter.issue_case_metadata[0]["initial_status"] == "open"

    def test_case_metadata_tracks_deterministic_id(self, converter):
        objects = converter.issues_to_stix([_full_issue()])
        case = next(o for o in objects if o.type == "case-incident")
        meta = converter.issue_case_metadata[0]
        assert meta["ticket_id"] == "HV-1"
        assert meta["case_incident_id"] == case.id
        assert meta["initial_status"] == "open:in_progress"

    def test_case_incident_id_is_deterministic(self, converter):
        first = converter.issues_to_stix([_full_issue()])
        second = converter.issues_to_stix([_full_issue()])
        case1 = next(o for o in first if o.type == "case-incident")
        case2 = next(o for o in second if o.type == "case-incident")
        assert case1.id == case2.id

    def test_note_id_stable_across_description_change(self, converter):
        # The Note id is seeded from the ticket id, not the mutable
        # description, so a status/progress change on re-import updates the
        # same Note instead of creating a duplicate.
        first = converter.issues_to_stix([_full_issue(status="open")])
        second = converter.issues_to_stix(
            [_full_issue(status="closed", progress_status="done")]
        )
        note1 = next(o for o in first if o.type == "note")
        note2 = next(o for o in second if o.type == "note")
        assert note1.id == note2.id
        assert note1.content != note2.content  # body still reflects latest state


class TestResolvedIssuesToStix:
    def test_resolved_issue(self, converter):
        objects = converter.resolved_issues_to_stix([_full_issue()])
        types = _types(objects)
        assert "vulnerability" in types
        assert "note" in types
        vuln = next(o for o in objects if o.type == "vulnerability")
        assert "resolved" in vuln.labels

    def test_resolved_without_ticket_id_skipped(self, converter):
        objects = converter.resolved_issues_to_stix([{"issue_name": "x"}])
        assert _types(objects) == ["identity"]

    def test_resolved_ip_only_system_named_by_ip(self, converter):
        # An IP-only resolved issue (no host/domain) must name the System by
        # the IP, not produce an empty-named System whose id collapses with
        # every other IP-only issue.
        objects = converter.resolved_issues_to_stix(
            [{"ticket_id": "HV-9", "issue_name": "x", "resolved_ip": "9.9.9.9"}]
        )
        systems = [
            o for o in objects if o.type == "identity" and o.identity_class == "system"
        ]
        assert len(systems) == 1
        assert systems[0].name == "9.9.9.9"

    def test_resolved_ip_only_systems_are_distinct(self, converter):
        a = converter.resolved_issues_to_stix(
            [{"ticket_id": "A", "issue_name": "x", "resolved_ip": "1.1.1.1"}]
        )
        b = converter.resolved_issues_to_stix(
            [{"ticket_id": "B", "issue_name": "y", "resolved_ip": "2.2.2.2"}]
        )
        sys_a = next(
            o.id for o in a if o.type == "identity" and o.identity_class == "system"
        )
        sys_b = next(
            o.id for o in b if o.type == "identity" and o.identity_class == "system"
        )
        assert sys_a != sys_b

    def test_resolved_note_id_stable_across_content_change(self, converter):
        a = converter.resolved_issues_to_stix([_full_issue(severity="high")])
        b = converter.resolved_issues_to_stix([_full_issue(severity="low")])
        note_a = next(o for o in a if o.type == "note")
        note_b = next(o for o in b if o.type == "note")
        assert note_a.id == note_b.id


class TestAssetsToStix:
    def test_domain_assets(self, converter):
        objects = converter.domain_assets_to_stix([{"domain": "a.com"}, {"domain": ""}])
        systems = [o for o in objects if o.type == "identity" and o.name == "a.com"]
        assert len(systems) == 1
        assert systems[0].identity_class == "system"

    def test_host_assets_plain_string(self, converter):
        objects = converter.host_assets_to_stix(["host1.example.com"])
        assert any(
            o.type == "identity" and o.name == "host1.example.com" for o in objects
        )

    def test_ip_assets(self, converter):
        objects = converter.ip_assets_to_stix([{"ip_address": "8.8.8.8"}])
        assert any(o.type == "identity" and o.name == "8.8.8.8" for o in objects)

    def test_empty_assets_only_author(self, converter):
        assert _types(converter.domain_assets_to_stix([])) == ["identity"]


class TestSoftwareDeterministicAcrossStix2:
    def test_same_name_same_id(self):
        a = stix2.Software(name="nginx")
        b = stix2.Software(name="nginx")
        assert a.id == b.id
