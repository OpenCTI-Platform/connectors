"""Fixture-driven tests for stix_builder.

Loads tests/fixtures/response.json (a real Hunter API capture) and asserts that
the builder produces a well-formed, schema-valid STIX 2.1 bundle for every
hunt in the response.
"""

from __future__ import annotations

import pytest
import stix2
from src import stix_builder


def _build_all_objects(response_payload):
    author = stix_builder.build_author()
    objects = [author]
    for hunt in response_payload["results"]:
        objects.extend(
            stix_builder.build_bundle(
                hunt, author, hunter_ui_base_url="https://hunter.example"
            )
        )
    return author, objects


def test_bundle_is_stix_valid(response_payload):
    _, objects = _build_all_objects(response_payload)
    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    # Round-trip via parse to assert the bundle is schema-valid.
    parsed = stix2.parse(bundle.serialize(), allow_custom=True)
    assert parsed.type == "bundle"
    assert len(parsed.objects) == len(objects)


def test_one_indicator_per_hunt(response_payload):
    _, objects = _build_all_objects(response_payload)
    indicators = [o for o in objects if o.type == "indicator"]
    assert len(indicators) == len(response_payload["results"])


def test_indicator_pattern_type_is_sigma(response_payload):
    _, objects = _build_all_objects(response_payload)
    for indicator in (o for o in objects if o.type == "indicator"):
        assert indicator.pattern_type == "sigma"
        assert indicator.pattern.strip()


def test_indicator_id_matches_hunt_uuid(response_payload, first_hunt):
    _, objects = _build_all_objects(response_payload)
    expected_id = f"indicator--{first_hunt['UUID'].lower()}"
    assert any(o.id == expected_id for o in objects)


def test_one_report_per_hunt(response_payload):
    _, objects = _build_all_objects(response_payload)
    reports = [o for o in objects if o.type == "report"]
    assert len(reports) == len(response_payload["results"])


def test_report_id_matches_hunt_uuid(response_payload, first_hunt):
    _, objects = _build_all_objects(response_payload)
    expected_id = f"report--{first_hunt['UUID'].lower()}"
    assert any(o.id == expected_id for o in objects)


def test_report_type_and_published_are_set(response_payload):
    _, objects = _build_all_objects(response_payload)
    for report in (o for o in objects if o.type == "report"):
        assert report.report_types == ["threat-hunting"]
        assert report.published is not None


def test_report_object_refs_populate_entities_tab(response_payload, first_hunt):
    """The Report's object_refs — the OpenCTI Entities tab — must contain the
    sigma Indicator and every related SDO built for the hunt."""
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(first_hunt, author)
    report = next(o for o in objects if o.type == "report")

    indicator_id = f"indicator--{first_hunt['UUID'].lower()}"
    assert indicator_id in report.object_refs

    entity_types = {
        "attack-pattern",
        "intrusion-set",
        "campaign",
        "malware",
        "vulnerability",
        "tool",
        "identity",
        "location",
    }
    related_ids = {
        o.id for o in objects if o.type in entity_types and o.id != author.id
    }
    assert related_ids, "fixture should yield related entities"
    assert related_ids.issubset(set(report.object_refs))


def test_report_object_refs_include_relationships(response_payload, first_hunt):
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(first_hunt, author)
    report = next(o for o in objects if o.type == "report")
    rel_ids = {o.id for o in objects if o.type == "relationship"}
    assert rel_ids
    assert rel_ids.issubset(set(report.object_refs))


def test_report_object_refs_have_no_duplicates(response_payload):
    _, objects = _build_all_objects(response_payload)
    for report in (o for o in objects if o.type == "report"):
        assert len(report.object_refs) == len(set(report.object_refs))


def test_report_score_reflects_severity(response_payload):
    _, objects = _build_all_objects(response_payload)
    by_uuid = {o.id.split("--", 1)[1]: o for o in objects if o.type == "report"}
    expected = {"high": 90, "medium": 60, "low": 30}
    for hunt in response_payload["results"]:
        report = by_uuid[hunt["UUID"].lower()]
        assert report.x_opencti_score == expected[hunt["severity"].lower()]


def test_score_reflects_severity(response_payload):
    _, objects = _build_all_objects(response_payload)
    by_uuid = {o.id.split("--", 1)[1]: o for o in objects if o.type == "indicator"}
    expected = {"high": 90, "medium": 60, "low": 30}
    for hunt in response_payload["results"]:
        indicator = by_uuid[hunt["UUID"].lower()]
        assert indicator.x_opencti_score == expected[hunt["severity"].lower()]


def test_indicator_has_external_references(response_payload):
    _, objects = _build_all_objects(response_payload)
    for indicator in (o for o in objects if o.type == "indicator"):
        sources = {ref.source_name for ref in indicator.external_references or []}
        assert "Intel 471 Hunter" in sources


def test_attack_patterns_have_x_mitre_id(response_payload):
    _, objects = _build_all_objects(response_payload)
    patterns = [o for o in objects if o.type == "attack-pattern"]
    assert patterns, "fixture should yield at least one MITRE attack-pattern"
    for ap in patterns:
        assert ap.x_mitre_id.startswith("T")
        # Kill chain phases come from tactics.
        assert all(
            p.kill_chain_name == "mitre-attack" for p in ap.kill_chain_phases or []
        )


def test_intrusion_set_created_for_actor(response_payload):
    _, objects = _build_all_objects(response_payload)
    names = {o.name for o in objects if o.type == "intrusion-set"}
    # TeamPCP appears in the first hunt's tags.actors
    assert "TeamPCP" in names


def test_campaign_created_for_campaign_tag(response_payload):
    _, objects = _build_all_objects(response_payload)
    names = {o.name for o in objects if o.type == "campaign"}
    assert "Shai-Hulud 2.0" in names


def test_malware_created_when_threat_category_is_malware(response_payload):
    _, objects = _build_all_objects(response_payload)
    names = {o.name for o in objects if o.type == "malware"}
    # The Shai-Hulud hunt tags threat_categories=Malware, threat_names=["Shai-Hulud"]
    assert "Shai-Hulud" in names


def test_relationships_link_indicator_to_related(response_payload):
    _, objects = _build_all_objects(response_payload)
    indicator_ids = {o.id for o in objects if o.type == "indicator"}
    relationships = [o for o in objects if o.type == "relationship"]
    indicates = [r for r in relationships if r.relationship_type == "indicates"]
    assert indicates
    assert all(r.source_ref in indicator_ids for r in indicates)


def test_intrusion_set_uses_attack_pattern_when_both_present(response_payload):
    _, objects = _build_all_objects(response_payload)
    uses = [
        r for r in objects if r.type == "relationship" and r.relationship_type == "uses"
    ]
    # First hunt has both an actor (TeamPCP) and MITRE techniques, so we expect
    # at least one intrusion-set -> attack-pattern uses relationship.
    assert uses


def test_notes_attached_to_report(response_payload, first_hunt):
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(first_hunt, author)
    report_id = f"report--{first_hunt['UUID'].lower()}"
    notes = [o for o in objects if o.type == "note"]
    assert notes
    for note in notes:
        assert report_id in note.object_refs


def test_running_analyst_notes_become_separate_notes(response_payload, first_hunt):
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(first_hunt, author)
    abstracts = [o.abstract for o in objects if o.type == "note"]
    # Three standing sections plus one Note per running_analyst_notes entry.
    assert "Analyst runbook" in abstracts
    assert any(a == "Additional Context" for a in abstracts)


def test_labels_include_severity_and_threat_categories(response_payload, first_hunt):
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(first_hunt, author)
    # The full context label set lives on the Report; the Indicator only carries
    # the severity label so it stays focused on the detection.
    report = next(o for o in objects if o.type == "report")
    assert "severity:high" in report.labels
    assert "Malware" in report.labels
    indicator = next(o for o in objects if o.type == "indicator")
    assert indicator.labels == ["severity:high"]


def test_trigger_entity_creates_indicator_relationship(first_hunt):
    """When triggered on a Threat-Actor-Group, the Indicator should link to it directly."""
    trigger = {
        "id": "threat-actor--234c8fea-c09a-5508-8eb1-e1f5521d6499",
        "type": "Threat-Actor-Group",
        "name": "TeamPCP",
    }
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(first_hunt, author, trigger_entity=trigger)
    relationships = [o for o in objects if o.type == "relationship"]
    indicates_trigger = [
        r
        for r in relationships
        if r.relationship_type == "indicates" and r.target_ref == trigger["id"]
    ]
    assert (
        indicates_trigger
    ), "expected an indicates relationship targeting the trigger entity"


def test_trigger_entity_added_to_report_object_refs(first_hunt):
    """The enriched entity should appear under the Report's Entities tab."""
    trigger = {
        "id": "threat-actor--234c8fea-c09a-5508-8eb1-e1f5521d6499",
        "type": "Threat-Actor-Group",
        "name": "TeamPCP",
    }
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(first_hunt, author, trigger_entity=trigger)
    report = next(o for o in objects if o.type == "report")
    assert trigger["id"] in report.object_refs


def test_trigger_entity_suppresses_duplicate_intrusion_set(first_hunt):
    trigger = {
        "id": "threat-actor--234c8fea-c09a-5508-8eb1-e1f5521d6499",
        "type": "Threat-Actor-Group",
        "name": "TeamPCP",
    }
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(first_hunt, author, trigger_entity=trigger)
    intrusion_set_names = {o.name for o in objects if o.type == "intrusion-set"}
    # tags.actors contains TeamPCP — we should NOT auto-create an Intrusion-Set duplicating the trigger.
    assert "TeamPCP" not in intrusion_set_names


def test_trigger_attack_pattern_matched_by_mitre_id(first_hunt):
    """A trigger Attack-Pattern is matched by x_mitre_id even if the name differs."""
    trigger = {
        "id": "attack-pattern--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "type": "Attack-Pattern",
        "name": "Some Localised Name",
        "x_mitre_id": "T1059.007",
    }
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(first_hunt, author, trigger_entity=trigger)
    # No auto-generated Attack-Pattern should carry T1059.007 — it's the trigger.
    auto_aps = [o for o in objects if o.type == "attack-pattern"]
    assert all(o.x_mitre_id != "T1059.007" for o in auto_aps)
    # Indicator should still have an indicates relationship to the trigger.
    relationships = [o for o in objects if o.type == "relationship"]
    assert any(
        r.relationship_type == "indicates" and r.target_ref == trigger["id"]
        for r in relationships
    )


def test_trigger_with_unknown_type_falls_through(first_hunt):
    # `tool` is now supported, so use an actually-unmapped entity type to verify
    # the no-op fallthrough behaviour.
    trigger = {
        "id": "channel--00000000-0000-4000-8000-000000000000",
        "type": "Channel",
        "name": "X",
    }
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(first_hunt, author, trigger_entity=trigger)
    rel_targets = {o.target_ref for o in objects if o.type == "relationship"}
    assert trigger["id"] not in rel_targets


def _enriched_hunt(first_hunt):
    """Augment the first fixture hunt with Tool/Sector/Country/Region tags.

    The captured fixture has these arrays empty; tests use this helper to
    exercise the new entity-creation paths without modifying the on-disk fixture.
    """
    return {
        **first_hunt,
        "tags": {
            **first_hunt["tags"],
            "tools": ["Cobalt Strike"],
            "tooling": ["Empire"],
            "target_industries": ["Financial Services", "Healthcare"],
            "target_countries": ["United States"],
            "source_countries": ["Russia"],
            "target_regions": ["Europe"],
            "source_regions": ["Asia"],
        },
    }


def test_tools_become_tool_entities(first_hunt):
    hunt = _enriched_hunt(first_hunt)
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(hunt, author)
    tool_names = {o.name for o in objects if o.type == "tool"}
    # Both `tools` and `tooling` populate Tool entities.
    assert tool_names == {"Cobalt Strike", "Empire"}


def test_target_industries_become_sector_entities(first_hunt):
    hunt = _enriched_hunt(first_hunt)
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(hunt, author)
    sectors = [
        o for o in objects if o.type == "identity" and o.identity_class == "class"
    ]
    assert {o.name for o in sectors} == {"Financial Services", "Healthcare"}


def test_target_and_source_countries_dedupe_into_country_entities(first_hunt):
    hunt = _enriched_hunt(first_hunt)
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(hunt, author)
    countries = [
        o
        for o in objects
        if o.type == "location"
        and getattr(o, "x_opencti_location_type", None) == "Country"
    ]
    assert {o.name for o in countries} == {"United States", "Russia"}


def test_target_and_source_regions_become_region_entities(first_hunt):
    hunt = _enriched_hunt(first_hunt)
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(hunt, author)
    regions = [
        o
        for o in objects
        if o.type == "location"
        and getattr(o, "x_opencti_location_type", None) == "Region"
    ]
    assert {o.name for o in regions} == {"Europe", "Asia"}


def test_indicator_indicates_new_entity_types(first_hunt):
    hunt = _enriched_hunt(first_hunt)
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(hunt, author)
    relationships = [o for o in objects if o.type == "relationship"]
    linked = {r.target_ref for r in relationships}
    new_entity_ids = {
        o.id for o in objects if o.type in {"tool", "identity", "location"}
    }
    # Every newly-created Tool/Sector/Location must be linked to the Indicator...
    assert new_entity_ids.issubset(linked)
    # ...but only Tool may use `indicates`: OpenCTI's schema rejects it for
    # Identity (Sector) and Location (Country/Region).
    by_id = {o.id: o for o in objects}
    for rel in relationships:
        target = by_id.get(rel.target_ref)
        if target is not None and target.type in {"identity", "location"}:
            assert rel.relationship_type == "related-to"


def test_tool_trigger_suppresses_duplicate(first_hunt):
    hunt = _enriched_hunt(first_hunt)
    trigger = {
        "id": "tool--11111111-1111-4111-8111-111111111111",
        "type": "Tool",
        "name": "Cobalt Strike",
    }
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(hunt, author, trigger_entity=trigger)
    tool_names = {o.name for o in objects if o.type == "tool"}
    assert "Cobalt Strike" not in tool_names  # trigger took its place
    assert "Empire" in tool_names  # other tool still created
    assert any(
        o.type == "relationship" and o.target_ref == trigger["id"] for o in objects
    )


def test_country_trigger_via_generic_location(first_hunt):
    hunt = _enriched_hunt(first_hunt)
    trigger = {
        "id": "location--22222222-2222-4222-8222-222222222222",
        "type": "Location",
        "name": "United States",
        "x_opencti_location_type": "Country",
    }
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(hunt, author, trigger_entity=trigger)
    countries = [
        o.name
        for o in objects
        if o.type == "location"
        and getattr(o, "x_opencti_location_type", None) == "Country"
    ]
    assert "United States" not in countries
    assert "Russia" in countries
    assert any(
        o.type == "relationship" and o.target_ref == trigger["id"] for o in objects
    )


def test_no_malware_when_threat_categories_lacks_malware(first_hunt):
    """Edit the fixture so threat_categories no longer says Malware — ensure no Malware object."""
    hunt = {**first_hunt, "tags": {**first_hunt["tags"], "threat_categories": []}}
    author = stix_builder.build_author()
    objects = stix_builder.build_bundle(hunt, author)
    assert not [o for o in objects if o.type == "malware"]
    # threat_names should have moved to labels prefixed with `threat:` on the Report.
    report = next(o for o in objects if o.type == "report")
    assert any(label.startswith("threat:") for label in report.labels)


def test_hunt_without_sigma_emits_no_indicator(first_hunt):
    """OpenCTI validates sigma with sigmatools and rejects an Indicator whose
    rule does not parse, which also breaks every relationship pointing at it.
    A hunt with no rule must yield a Report and context, never a placeholder."""
    hunt = dict(first_hunt)
    hunt.pop("sigma", None)
    author = stix_builder.build_author()

    objects = stix_builder.build_bundle(hunt, author)

    assert not [o for o in objects if o["type"] == "indicator"]
    reports = [o for o in objects if o["type"] == "report"]
    assert len(reports) == 1
    # No dangling references: everything in object_refs is in the bundle or is
    # the trigger entity.
    ids = {o["id"] for o in objects}
    assert all(ref in ids for ref in reports[0]["object_refs"])


def test_hunt_with_blank_sigma_emits_no_indicator(first_hunt):
    hunt = dict(first_hunt)
    hunt["sigma"] = "   "
    author = stix_builder.build_author()

    objects = stix_builder.build_bundle(hunt, author)

    assert not [o for o in objects if o["type"] == "indicator"]


def test_emitted_sigma_patterns_parse(response_payload):
    """Every pattern we emit must satisfy pySigma, the parser OpenCTI validates
    with. Hunter rules carry metadata pySigma rejects (status: New, non-UUID
    ids, nested tags); src.sigma_rule normalises it before we emit."""
    collection = pytest.importorskip("sigma.collection", reason="pysigma not installed")
    author = stix_builder.build_author()

    emitted = 0
    for hunt in response_payload["results"]:
        for obj in stix_builder.build_bundle(hunt, author):
            if obj["type"] == "indicator":
                assert obj["pattern_type"] == "sigma"
                collection.SigmaCollection.from_yaml(obj["pattern"])
                emitted += 1
    # The fixture is all sigma-bearing hunts: every one must produce a rule.
    assert emitted == len(response_payload["results"])


def test_indicates_only_targets_types_opencti_allows(response_payload):
    """OpenCTI's schema forbids `indicates` from an Indicator to Identity or
    Location; those must use `related-to` or the platform rejects them."""
    author = stix_builder.build_author()
    allowed = stix_builder._INDICATES_VALID_TARGETS

    for hunt in response_payload["results"]:
        objects = stix_builder.build_bundle(hunt, author)
        by_id = {o["id"]: o for o in objects}
        for obj in objects:
            if obj["type"] != "relationship":
                continue
            if obj["relationship_type"] != "indicates":
                continue
            target = by_id.get(obj["target_ref"])
            if target is not None:
                assert (
                    target["type"] in allowed
                ), f"indicates -> {target['type']} is rejected by OpenCTI"


def test_sector_and_location_use_related_to(response_payload):
    author = stix_builder.build_author()
    seen = set()

    for hunt in response_payload["results"]:
        objects = stix_builder.build_bundle(hunt, author)
        by_id = {o["id"]: o for o in objects}
        for obj in objects:
            if obj["type"] != "relationship":
                continue
            target = by_id.get(obj["target_ref"])
            if target is not None and target["type"] in ("identity", "location"):
                seen.add(target["type"])
                assert obj["relationship_type"] == "related-to"

    assert seen, "fixture should contain sector/location entities"


def test_trigger_relationship_respects_the_same_rule():
    author = stix_builder.build_author()
    hunt = {
        "UUID": "11111111-1111-4111-8111-111111111111",
        "title": "t",
        "sigma": (
            "title: t\nlogsource:\n  category: process_creation\n"
            "detection:\n  selection:\n    Image: x\n  condition: selection\n"
        ),
    }

    country_trigger = {
        "id": "location--22222222-2222-4222-8222-222222222222",
        "type": "Country",
        "name": "Poland",
    }
    objects = stix_builder.build_bundle(hunt, author, trigger_entity=country_trigger)
    rels = [o for o in objects if o["type"] == "relationship"]
    assert rels and all(r["relationship_type"] == "related-to" for r in rels)

    malware_trigger = {
        "id": "malware--33333333-3333-4333-8333-333333333333",
        "type": "Malware",
        "name": "SmokedHam",
    }
    objects = stix_builder.build_bundle(hunt, author, trigger_entity=malware_trigger)
    rels = [o for o in objects if o["type"] == "relationship"]
    assert rels and all(r["relationship_type"] == "indicates" for r in rels)


def test_note_ids_survive_a_hunt_republish(first_hunt):
    """A Note id must not fold in a timestamp: Hunter republishes hunts, and an
    id keyed on `last_updated` would mint duplicates on every re-enrichment."""
    author = stix_builder.build_author()
    hunt = dict(first_hunt)

    hunt["last_updated"] = "2026-05-13T15:36:15.873627+00:00"
    before = {
        o["id"] for o in stix_builder.build_bundle(hunt, author) if o["type"] == "note"
    }
    hunt["last_updated"] = "2026-08-27T09:00:00.000000+00:00"
    after = {
        o["id"] for o in stix_builder.build_bundle(hunt, author) if o["type"] == "note"
    }

    assert before and before == after


def test_notes_carry_entity_markings(first_hunt):
    markings = ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"]
    author = stix_builder.build_author()

    objects = stix_builder.build_bundle(first_hunt, author, markings=markings)

    notes = [o for o in objects if o["type"] == "note"]
    assert notes
    assert all(o["object_marking_refs"] == markings for o in notes)


def test_notes_with_same_text_but_different_abstract_stay_distinct(first_hunt):
    author = stix_builder.build_author()
    hunt = dict(first_hunt)
    shared = "Identical text in two sections."
    hunt["response_actions"] = {
        "analyst_runbook": shared,
        "mitigation_recommendations": shared,
    }

    notes = [o for o in stix_builder.build_bundle(hunt, author) if o["type"] == "note"]

    ids = [o["id"] for o in notes if o["content"] == shared]
    assert len(ids) == 2 and len(set(ids)) == 2
