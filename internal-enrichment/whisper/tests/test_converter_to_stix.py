import logging

import pytest
import stix2
from connector.converter_to_stix import (
    ALLOWED_RELATIONSHIPS,
    NODE_MAPPERS,
    WHISPER_AUTHOR,
    build_bundle,
    build_note,
    map_edge,
    map_node,
)
from connector.exceptions import StixMappingError

# --- SCO mappers -----------------------------------------------------------


def test_map_ipv4():
    obj = map_node(
        {"id": "w-1", "type": "ipv4-addr", "properties": {"value": "1.2.3.4"}}
    )
    assert isinstance(obj, stix2.IPv4Address)
    assert obj.value == "1.2.3.4"


def test_map_ipv6():
    obj = map_node(
        {"id": "w-2", "type": "ipv6-addr", "properties": {"value": "2001:db8::1"}}
    )
    assert isinstance(obj, stix2.IPv6Address)
    assert obj.value == "2001:db8::1"


def test_map_domain():
    obj = map_node(
        {"id": "w-3", "type": "domain-name", "properties": {"value": "evil.test"}}
    )
    assert isinstance(obj, stix2.DomainName)
    assert obj.value == "evil.test"


def test_map_url():
    obj = map_node(
        {"id": "w-4", "type": "url", "properties": {"value": "https://evil.test/p"}}
    )
    assert isinstance(obj, stix2.URL)
    assert obj.value == "https://evil.test/p"


def test_map_email():
    obj = map_node(
        {"id": "w-5", "type": "email-addr", "properties": {"value": "a@b.test"}}
    )
    assert isinstance(obj, stix2.EmailAddress)
    assert obj.value == "a@b.test"


def test_map_autonomous_system():
    obj = map_node(
        {
            "id": "w-6",
            "type": "autonomous-system",
            "properties": {"number": 64500, "name": "TEST"},
        }
    )
    assert isinstance(obj, stix2.AutonomousSystem)
    assert obj.number == 64500
    assert obj.name == "TEST"


def test_map_autonomous_system_number_coerced():
    obj = map_node(
        {"id": "w-7", "type": "autonomous-system", "properties": {"number": "64501"}}
    )
    assert obj.number == 64501


def test_map_file_with_all_hashes():
    obj = map_node(
        {
            "id": "w-8",
            "type": "file",
            "properties": {
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "name": "empty.bin",
            },
        }
    )
    assert isinstance(obj, stix2.File)
    assert obj.hashes["MD5"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert obj.hashes["SHA-1"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert obj.hashes["SHA-256"] == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert obj.name == "empty.bin"


def test_map_file_name_only_ok():
    obj = map_node({"id": "w-9", "type": "file", "properties": {"name": "x.bin"}})
    assert obj.name == "x.bin"


def test_map_file_requires_hash_or_name():
    with pytest.raises(StixMappingError):
        map_node({"id": "w-10", "type": "file", "properties": {}})


# --- SDO mappers -----------------------------------------------------------


def test_map_threat_actor_deterministic_id():
    node = {
        "id": "w-actor-1",
        "type": "threat-actor",
        "properties": {"name": "APT-Test", "description": "test actor"},
    }
    obj_a = map_node(node)
    obj_b = map_node(node)
    assert isinstance(obj_a, stix2.ThreatActor)
    assert obj_a.id == obj_b.id  # idempotent
    assert obj_a.id.startswith("threat-actor--")
    assert obj_a.name == "APT-Test"
    assert obj_a.description == "test actor"


def test_map_malware_deterministic_id_and_is_family():
    node = {
        "id": "w-mal-1",
        "type": "malware",
        "properties": {"name": "TestMal", "is_family": True},
    }
    obj = map_node(node)
    assert isinstance(obj, stix2.Malware)
    assert obj.name == "TestMal"
    assert obj.is_family is True
    assert obj.id == map_node(node).id


def test_map_location_deterministic_id_and_country():
    # Issue #48 follow-up: Whisper COUNTRY nodes → STIX Location SDOs
    # with the ISO 3166-1 alpha-2 code in the `country` field. UUIDv5 ID
    # keyed off the Whisper node ID so re-enrichment is idempotent.
    node = {
        "id": "w-country-us-1",
        "type": "location",
        "properties": {"country": "US"},
    }
    obj_a = map_node(node)
    obj_b = map_node(node)
    assert isinstance(obj_a, stix2.Location)
    assert obj_a.id.startswith("location--")
    assert obj_a.id == obj_b.id  # idempotent
    assert obj_a.country == "US"


def test_map_location_with_city_country_and_name():
    # Whisper CITY nodes give us city + country code; the Location SDO
    # carries both plus the original full string as the human-readable
    # name.
    node = {
        "id": "w-city-1",
        "type": "location",
        "properties": {
            "city": "Mountain View",
            "country": "US",
            "name": "Mountain View, US",
        },
    }
    obj = map_node(node)
    assert isinstance(obj, stix2.Location)
    assert obj.city == "Mountain View"
    assert obj.country == "US"
    assert obj.name == "Mountain View, US"


def test_map_location_without_country_or_region_raises():
    # STIX 2.1 Location requires at least one of country/region/lat-long.
    # The parser drops Location nodes that lack a country, but the mapper
    # is defensive and raises StixMappingError if it ever sees one anyway.
    node = {
        "id": "w-bad-loc",
        "type": "location",
        "properties": {"name": "Just A Name Without Country"},
    }
    with pytest.raises(StixMappingError):
        map_node(node)


def test_map_identity_deterministic_id_and_class():
    # Whisper ORGANIZATION / REGISTRAR nodes → STIX Identity SDOs.
    node = {
        "id": "w-org-1",
        "type": "identity",
        "properties": {"name": "Google LLC", "identity_class": "organization"},
    }
    obj_a = map_node(node)
    obj_b = map_node(node)
    assert isinstance(obj_a, stix2.Identity)
    assert obj_a.id.startswith("identity--")
    assert obj_a.id == obj_b.id  # idempotent
    assert obj_a.name == "Google LLC"
    assert obj_a.identity_class == "organization"


# --- Validation -------------------------------------------------------------


def test_map_node_unknown_type_raises():
    with pytest.raises(StixMappingError, match="unsupported node type"):
        map_node({"id": "w-x", "type": "made-up", "properties": {}})


def test_map_node_missing_id_or_type_raises():
    with pytest.raises(StixMappingError):
        map_node({"type": "ipv4-addr", "properties": {"value": "1.1.1.1"}})
    with pytest.raises(StixMappingError):
        map_node({"id": "w-x", "properties": {}})


def test_map_node_missing_required_property_raises():
    with pytest.raises(StixMappingError, match="missing required properties"):
        map_node({"id": "w-x", "type": "ipv4-addr", "properties": {}})


def test_map_node_handles_none_properties():
    with pytest.raises(StixMappingError):
        map_node({"id": "w-x", "type": "ipv4-addr"})


# --- Edge / Relationship ---------------------------------------------------


def test_map_edge_builds_relationship():
    src = map_node(
        {"id": "n1", "type": "ipv4-addr", "properties": {"value": "1.1.1.1"}}
    )
    dst = map_node(
        {"id": "n2", "type": "domain-name", "properties": {"value": "x.test"}}
    )
    edge = {
        "id": "e1",
        "source_id": "n1",
        "target_id": "n2",
        "type": "resolves-to",
        "properties": {"description": "first seen 2026-01-01"},
    }
    rel = map_edge(edge, src, dst)
    assert isinstance(rel, stix2.Relationship)
    assert rel.relationship_type == "resolves-to"
    assert rel.source_ref == src.id
    assert rel.target_ref == dst.id
    assert rel.description == "first seen 2026-01-01"


def test_map_edge_deterministic_id_without_explicit_id():
    src = map_node(
        {"id": "n1", "type": "ipv4-addr", "properties": {"value": "1.1.1.1"}}
    )
    dst = map_node(
        {"id": "n2", "type": "domain-name", "properties": {"value": "x.test"}}
    )
    edge = {"source_id": "n1", "target_id": "n2", "type": "resolves-to"}
    rel_a = map_edge(edge, src, dst)
    rel_b = map_edge(edge, src, dst)
    assert rel_a.id == rel_b.id


def test_map_edge_unknown_type_raises():
    src = map_node(
        {"id": "n1", "type": "ipv4-addr", "properties": {"value": "1.1.1.1"}}
    )
    dst = map_node(
        {"id": "n2", "type": "domain-name", "properties": {"value": "x.test"}}
    )
    with pytest.raises(StixMappingError, match="unsupported relationship type"):
        map_edge({"source_id": "n1", "target_id": "n2", "type": "made-up"}, src, dst)


def test_map_edge_missing_fields_raises():
    src = map_node(
        {"id": "n1", "type": "ipv4-addr", "properties": {"value": "1.1.1.1"}}
    )
    dst = map_node(
        {"id": "n2", "type": "domain-name", "properties": {"value": "x.test"}}
    )
    with pytest.raises(StixMappingError):
        map_edge({"target_id": "n2", "type": "resolves-to"}, src, dst)


def test_allowed_relationships_documented():
    expected = {
        "communicates-with",
        "resolves-to",
        "related-to",
        "attributed-to",
        "uses",
        "indicates",
        "downloads",
        "hosts",
    }
    assert ALLOWED_RELATIONSHIPS == expected


# --- Bundle ---------------------------------------------------------------


def test_build_bundle_round_trips_through_stix2_parse():
    nodes = [
        {"id": "n1", "type": "ipv4-addr", "properties": {"value": "1.1.1.1"}},
        {"id": "n2", "type": "domain-name", "properties": {"value": "x.test"}},
        {"id": "n3", "type": "threat-actor", "properties": {"name": "APT-Test"}},
    ]
    edges = [
        {"source_id": "n1", "target_id": "n2", "type": "resolves-to"},
        {"source_id": "n2", "target_id": "n3", "type": "attributed-to"},
    ]
    bundle = build_bundle(nodes, edges)
    assert isinstance(bundle, stix2.Bundle)
    # 3 nodes + 2 relationships + the prepended WHISPER_AUTHOR Identity.
    assert len(bundle.objects) == 6
    assert bundle.objects[0] == WHISPER_AUTHOR

    # allow_custom=True: the SCOs carry the x_opencti_created_by_ref custom
    # property (see the VC302 author convention in converter_to_stix).
    parsed = stix2.parse(bundle.serialize(), allow_custom=True)
    assert isinstance(parsed, stix2.Bundle)
    assert len(parsed.objects) == 6


def test_build_bundle_edge_unknown_node_raises():
    nodes = [{"id": "n1", "type": "ipv4-addr", "properties": {"value": "1.1.1.1"}}]
    edges = [{"source_id": "n1", "target_id": "missing", "type": "resolves-to"}]
    with pytest.raises(StixMappingError, match="unknown node id"):
        build_bundle(nodes, edges)


@pytest.mark.parametrize("rel_type", ["related-to", "resolves-to"])
def test_build_bundle_skips_self_loop_relationship(rel_type, caplog):
    # Distinct Whisper nodes can collapse onto one deterministic STIX ID —
    # e.g. a domain that is its own nameserver arrives as two HOSTNAME
    # nodes with the same value. OpenCTI rejects every same-source-target
    # relationship (worker UNSUPPORTED_ERROR), so build_bundle must drop
    # the edge instead of shipping it.
    nodes = [
        {"id": "w-dom", "type": "domain-name", "properties": {"value": "ns.test"}},
        {"id": "w-ns", "type": "domain-name", "properties": {"value": "ns.test"}},
    ]
    edges = [
        {
            "source_id": "w-dom",
            "target_id": "w-ns",
            "type": rel_type,
            "properties": {"description": "name-server"},
        }
    ]
    with caplog.at_level(logging.INFO, logger="connector.converter_to_stix"):
        bundle = build_bundle(nodes, edges)
    types = [o["type"] for o in bundle.objects]
    assert "relationship" not in types
    # build_bundle does not dedup node objects, so both same-value nodes
    # land in the bundle (same STIX ID twice); OpenCTI dedups on ingest.
    assert types.count("domain-name") == 2
    assert bundle.objects[0] == WHISPER_AUTHOR
    # The skip is logged at info with the shared STIX ID and rel type for
    # QA traceability.
    shared_id = stix2.DomainName(value="ns.test").id
    assert any(
        "skipping self-loop relationship" in msg
        and shared_id in msg
        and rel_type in msg
        for msg in caplog.messages
    )


def test_build_bundle_normal_edge_control_still_emits_relationship():
    # Control for the self-loop guard: distinct-value endpoints must keep
    # producing their relationship, refs intact.
    nodes = [
        {"id": "w-dom", "type": "domain-name", "properties": {"value": "a.test"}},
        {"id": "w-ns", "type": "domain-name", "properties": {"value": "ns.test"}},
    ]
    edges = [
        {
            "source_id": "w-dom",
            "target_id": "w-ns",
            "type": "related-to",
            "properties": {"description": "name-server"},
        }
    ]
    bundle = build_bundle(nodes, edges)
    rels = [o for o in bundle.objects if o["type"] == "relationship"]
    assert len(rels) == 1
    assert rels[0].source_ref == stix2.DomainName(value="a.test").id
    assert rels[0].target_ref == stix2.DomainName(value="ns.test").id


def test_build_bundle_empty_inputs():
    # stix2 strips empty collection fields, so `.objects` is absent on an
    # empty bundle. The caller in #7 must guard against this rather than
    # sending an empty bundle to OpenCTI.
    bundle = build_bundle([], [])
    assert isinstance(bundle, stix2.Bundle)
    assert "objects" not in bundle


# --- Author attribution (VC302) ---------------------------------------------
# Every object the connector emits must reference the Whisper author
# Identity: SDOs/SROs/Notes via created_by_ref, SCOs via the OpenCTI
# x_opencti_created_by_ref custom property (STIX 2.1 forbids
# created_by_ref on SCOs).


def test_author_identity_is_deterministic_and_self_authored():
    # pycti hashes exactly (name, identity_class), so the ID is stable
    # across runs, connectors, and the upstream port.
    import pycti

    assert WHISPER_AUTHOR.id == pycti.Identity.generate_id(
        name="Whisper", identity_class="organization"
    )
    assert WHISPER_AUTHOR.identity_class == "organization"
    # The author Identity itself carries no created_by_ref.
    assert "created_by_ref" not in WHISPER_AUTHOR


def test_sco_carries_x_opencti_created_by_ref():
    obj = map_node(
        {"id": "w-1", "type": "ipv4-addr", "properties": {"value": "1.2.3.4"}}
    )
    assert obj.x_opencti_created_by_ref == WHISPER_AUTHOR.id
    # The custom property must not perturb the spec-deterministic SCO ID.
    assert obj.id == stix2.IPv4Address(value="1.2.3.4").id


@pytest.mark.parametrize(
    "node",
    [
        {"id": "w-a", "type": "threat-actor", "properties": {"name": "APT-Test"}},
        {"id": "w-b", "type": "malware", "properties": {"name": "TestMal"}},
        {"id": "w-c", "type": "location", "properties": {"country": "US"}},
        {"id": "w-d", "type": "identity", "properties": {"name": "Google LLC"}},
    ],
)
def test_sdo_carries_created_by_ref(node):
    obj = map_node(node)
    assert obj.created_by_ref == WHISPER_AUTHOR.id


def test_relationship_carries_created_by_ref():
    src = map_node(
        {"id": "n1", "type": "ipv4-addr", "properties": {"value": "1.1.1.1"}}
    )
    dst = map_node(
        {"id": "n2", "type": "domain-name", "properties": {"value": "x.test"}}
    )
    rel = map_edge(
        {"source_id": "n1", "target_id": "n2", "type": "resolves-to"}, src, dst
    )
    assert rel.created_by_ref == WHISPER_AUTHOR.id


def test_note_carries_created_by_ref_without_rekeying_id():
    # created_by_ref must not change the Note ID — pycti.Note.generate_id
    # only hashes (created, content, abstract).
    import pycti

    note = build_note(
        "ipv4-addr--00000000-0000-4000-8000-000000000000", "content", abstract="abs"
    )
    assert note.created_by_ref == WHISPER_AUTHOR.id
    assert note.id == pycti.Note.generate_id(None, "content", "abs")


def test_build_bundle_with_sco_allows_custom_and_prepends_author():
    # Regression guard for the allow_custom=True requirement: an SCO in the
    # bundle carries a custom property, and stix2.Bundle raises without
    # allow_custom. The author Identity leads the object list.
    nodes = [{"id": "n1", "type": "ipv4-addr", "properties": {"value": "8.8.8.8"}}]
    note = build_note(
        "ipv4-addr--00000000-0000-4000-8000-000000000000", "threat context"
    )
    bundle = build_bundle(nodes, [], extra_objects=[note])
    assert bundle.objects[0] == WHISPER_AUTHOR
    assert [o["type"] for o in bundle.objects] == ["identity", "ipv4-addr", "note"]


def test_build_bundle_empty_inputs_has_no_author():
    # No data → no bundle content at all; the author is only prepended
    # when there is something to attribute.
    bundle = build_bundle([], [])
    assert "objects" not in bundle


def test_every_node_type_has_a_mapper_smoke():
    # Catches accidental key/case drift between code and tests.
    expected_types = {
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "url",
        "email-addr",
        "autonomous-system",
        "file",
        "threat-actor",
        "malware",
        "location",
        "identity",
    }
    assert set(NODE_MAPPERS.keys()) == expected_types
