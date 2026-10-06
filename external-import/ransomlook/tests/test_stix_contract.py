"""Integration-level STIX bundle contract tests."""

# pylint: disable=wrong-import-order

import stix2
from connector.converter import RansomLookConverter
from pycti import OpenCTIConnectorHelper


def test_claim_graph_serializes_through_pycti_and_stix_parser():
    """Ensure a complete claim graph survives the pycti bundle boundary."""
    converter = RansomLookConverter(
        "https://www.ransomlook.io/api",
        ["ransomware", "ransomlook"],
        "TLP:CLEAR",
    )
    post = {
        "group_name": "akira",
        "post_title": "Example Corp",
        "discovered": "2026-01-02T03:04:05Z",
        "description": "Claim description",
        "website": "https://example.com",
    }
    group = converter.create_group("akira", {"meta": "Group description"})
    victim = converter.create_victim("Example Corp")
    incident = converter.create_incident(post)
    relationships = [
        converter.create_relationship(incident.id, "attributed-to", group.id),
        converter.create_relationship(incident.id, "targets", victim.id),
    ]
    observables = converter.create_website_observables(post["website"])
    observable_relationships = [
        converter.create_relationship(observable.id, "related-to", victim.id)
        for observable in observables
    ]
    graph = [group, victim, incident, *relationships, *observables]
    graph.extend(observable_relationships)
    report = converter.create_report(post, [obj.id for obj in graph])
    note = converter.create_note(
        {"id": "note-1", "name": "Akira ransom note", "content": "Pay us"},
        group.id,
    )
    graph.extend([report, note, converter.author, converter.marking])

    bundle_json = OpenCTIConnectorHelper.stix2_create_bundle(graph.copy())
    bundle = stix2.parse(bundle_json, allow_custom=True, version="2.1")
    object_ids = {obj.id for obj in bundle.objects}

    assert bundle.spec_version == "2.1"
    assert len(bundle.objects) == len(graph)
    for relationship in relationships + observable_relationships:
        assert relationship.source_ref in object_ids
        assert relationship.target_ref in object_ids
    parsed_report = next(obj for obj in bundle.objects if obj.id == report.id)
    assert parsed_report.created_by_ref == converter.author.id
    assert set(parsed_report.object_refs) <= object_ids
    assert set(note.object_refs) <= object_ids


def test_actor_infrastructure_serializes_and_remains_outside_claim_report():
    converter = RansomLookConverter(
        "https://www.ransomlook.io/api", ["ransomware"], "TLP:CLEAR"
    )
    group = converter.create_group("akira", {})
    profile = converter.create_location_infrastructure(
        "akira",
        {
            "slug": "http://historic.example/",
            "available": False,
            "lastscrape": "2026-01-01T00:00:00Z",
        },
    )
    uses = converter.create_relationship(group.id, "uses", profile[0].id)
    report = converter.create_report(
        {
            "group_name": "akira",
            "post_title": "Example Corp",
            "discovered": "2026-01-02T00:00:00Z",
        },
        [group.id],
    )
    graph = [group, *profile, uses, report, converter.author, converter.marking]
    bundle = stix2.parse(
        OpenCTIConnectorHelper.stix2_create_bundle(graph.copy()),
        allow_custom=True,
        version="2.1",
    )
    assert any(obj.type == "infrastructure" for obj in bundle.objects)
    assert profile[0].id not in report.object_refs
    assert uses.target_ref == profile[0].id


def test_named_actor_profile_serializes_and_remains_outside_claim_report():
    converter = RansomLookConverter(
        "https://www.ransomlook.io/api", ["ransomware"], "TLP:CLEAR"
    )
    group = converter.create_group("akira", {})
    actor = converter.create_named_actor(
        {
            "name": "example-person",
            "aliases": ["example-alias"],
            "contacts": {"telegram": "example-contact"},
            "relations": {"groups": ["akira"]},
        }
    )
    relation = converter.create_profile_relationship(actor.id, group.id, "group")
    report = converter.create_report(
        {
            "group_name": "akira",
            "post_title": "Example Corp",
            "discovered": "2026-01-02T03:04:05Z",
        },
        [group.id],
    )
    assert actor.id not in report.object_refs
    assert relation.id not in report.object_refs
    graph = [actor, group, relation, report, converter.author, converter.marking]
    bundle = stix2.parse(
        OpenCTIConnectorHelper.stix2_create_bundle(graph.copy()),
        allow_custom=True,
        version="2.1",
    )
    assert any(obj.type == "threat-actor" for obj in bundle.objects)


def test_note_evidence_and_wallet_serialize_as_profile_context():
    converter = RansomLookConverter(
        "https://www.ransomlook.io/api", ["ransomware"], "TLP:CLEAR"
    )
    group = converter.create_group("akira", {})
    note = converter.create_note(
        {"id": "n-1", "title": "Original note", "content": "Pay us"}, group.id
    )
    wallet = converter.create_wallet({"address": "bc1qexample"}, "bitcoin")
    relation = converter.create_relationship(group.id, "related-to", wallet.id)
    bundle = OpenCTIConnectorHelper.stix2_create_bundle(
        [group, note, wallet, relation, converter.author, converter.marking]
    )
    parsed = stix2.parse(bundle, allow_custom=True, version="2.1")
    assert {obj.type for obj in parsed.objects} >= {
        "note",
        "cryptocurrency-wallet",
        "relationship",
    }
    assert not any(obj.type == "indicator" for obj in parsed.objects)


def test_torrent_magnet_webseed_and_direct_leak_serialize_without_indicators():
    converter = RansomLookConverter(
        "https://www.ransomlook.io/api", ["ransomware"], "TLP:CLEAR"
    )
    post = {
        "id": "claim-1",
        "group_name": "akira",
        "post_title": "Example Corp",
        "discovered": "2026-01-02T03:04:05Z",
    }
    incident = converter.create_incident(post)
    magnet = converter.create_magnet_observable({"infohash": "b" * 40})
    webseed = converter.create_website_observables("https://seed.example/file")[-1]
    leak = converter.create_leak_note({"id": 42, "name": "Exact leak"}, incident.id)
    relations = [
        converter.create_relationship(webseed.id, "related-to", magnet.id),
        converter.create_direct_leak_relationship(magnet.id, incident.id, "torrent"),
        converter.create_direct_leak_relationship(leak.id, incident.id, "leak"),
    ]
    report = converter.create_report(
        post,
        [incident.id, magnet.id, webseed.id, leak.id, *[rel.id for rel in relations]],
    )
    graph = [
        incident,
        magnet,
        webseed,
        leak,
        *relations,
        report,
        converter.author,
        converter.marking,
    ]
    parsed = stix2.parse(
        OpenCTIConnectorHelper.stix2_create_bundle(graph.copy()),
        allow_custom=True,
        version="2.1",
    )
    assert {obj.type for obj in parsed.objects} >= {
        "url",
        "note",
        "relationship",
        "report",
    }
    assert not any(obj.type == "indicator" for obj in parsed.objects)
    assert set(report.object_refs) <= {obj.id for obj in parsed.objects}
