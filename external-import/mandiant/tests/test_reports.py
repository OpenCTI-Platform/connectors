from types import SimpleNamespace

from connector.reports import MandiantReport


def _build_report(bundle):
    connector = SimpleNamespace(
        identity={"standard_id": "identity--author"},
        mandiant_report_types={"Threat Activity Report": "threat-activity-report"},
        mandiant_create_notes=False,
        mandiant_import_software_cpe=True,
        guess_relationships_reports=[],
    )
    return MandiantReport(
        bundle=bundle,
        details={"report_id": "report-1"},
        pdf=None,
        connector=connector,
        report_type="Threat Activity Report",
        report_link="https://example.com/report",
    )


def test_adds_indicator_observables_and_based_on_relationships():
    bundle = {
        "objects": [
            {"type": "report", "id": "report--1", "object_refs": ["indicator--1"]},
            {"type": "indicator", "id": "indicator--1"},
            {"type": "ipv4-addr", "id": "ipv4-addr--1"},
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "based-on",
                "source_ref": "indicator--1",
                "target_ref": "ipv4-addr--1",
            },
        ]
    }
    report = _build_report(bundle)

    report.add_indicator_observable_references()

    assert bundle["objects"][0]["object_refs"] == [
        "indicator--1",
        "relationship--1",
        "ipv4-addr--1",
    ]


def test_excludes_non_indicator_based_on_relationships():
    bundle = {
        "objects": [
            {"type": "report", "id": "report--1", "object_refs": ["indicator--1"]},
            {"type": "indicator", "id": "indicator--1"},
            {"type": "domain-name", "id": "domain-name--1"},
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "related-to",
                "source_ref": "indicator--1",
                "target_ref": "domain-name--1",
            },
            {
                "type": "relationship",
                "id": "relationship--2",
                "relationship_type": "based-on",
                "source_ref": "malware--1",
                "target_ref": "domain-name--1",
            },
        ]
    }
    report = _build_report(bundle)

    report.add_indicator_observable_references()

    assert bundle["objects"][0]["object_refs"] == ["indicator--1"]
