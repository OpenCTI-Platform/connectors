import json

from connector.stix_builder import (
    bundle,
    make_autonomous_system,
    make_domain,
    make_external_reference,
    make_ipv4,
    make_ipv6,
    make_note,
    make_relationship,
    network_observable_for,
    stix_id,
    tlp_marking,
)


def test_stix_id_is_deterministic():
    a = stix_id("note", "stairwell-ai-triage|file--abc")
    b = stix_id("note", "stairwell-ai-triage|file--abc")
    assert a == b
    assert a.startswith("note--")


def test_tlp_marking_default_amber():
    assert "marking-definition--" in tlp_marking("amber")
    assert tlp_marking("AMBER") == tlp_marking("amber")
    assert tlp_marking("not-a-tlp") == tlp_marking("amber")


def test_make_ipv4_and_ipv6_have_correct_type():
    v4 = make_ipv4("8.8.8.8")
    v6 = make_ipv6("2001:db8::1")
    assert v4["type"] == "ipv4-addr"
    assert v4["value"] == "8.8.8.8"
    assert v6["type"] == "ipv6-addr"
    assert v6["value"] == "2001:db8::1"
    assert v4["object_marking_refs"] == [tlp_marking("amber")]


def test_network_observable_for_picks_ipv6_by_colon():
    assert network_observable_for("8.8.8.8", "ip", "amber")["type"] == "ipv4-addr"
    assert network_observable_for("2001:db8::1", "ip", "amber")["type"] == "ipv6-addr"
    assert (
        network_observable_for("evil.com", "hostname", "amber")["type"] == "domain-name"
    )
    assert network_observable_for("http://evil.com/x", "url", "amber")["type"] == "url"
    assert network_observable_for("", "ip", "amber") is None
    assert network_observable_for("x", "unknown-kind", "amber") is None


def test_make_domain_and_asn_basic_shape():
    d = make_domain("evil.com")
    asn = make_autonomous_system(15169, name="GOOGLE")
    assert d["type"] == "domain-name"
    assert d["value"] == "evil.com"
    assert asn["type"] == "autonomous-system"
    assert asn["number"] == 15169
    assert asn["name"] == "GOOGLE"


def test_make_relationship_deterministic_id():
    a = make_relationship("file--x", "ipv4-addr--y")
    b = make_relationship("file--x", "ipv4-addr--y")
    assert a["id"] == b["id"]
    assert a["relationship_type"] == "related-to"


def test_make_note_includes_object_refs_and_tlp():
    note = make_note(
        seed="stairwell-test|file--x",
        abstract="Test",
        content="body",
        object_refs=["file--x"],
        tlp="green",
    )
    assert note["type"] == "note"
    assert note["object_refs"] == ["file--x"]
    assert note["object_marking_refs"] == [tlp_marking("green")]


def test_bundle_dedupes_by_id_and_serializes():
    objs = [
        make_ipv4("8.8.8.8"),
        make_ipv4("8.8.8.8"),  # duplicate
        make_domain("evil.com"),
    ]
    payload = json.loads(bundle(objs))
    assert payload["type"] == "bundle"
    ids = {o["id"] for o in payload["objects"]}
    assert len(ids) == 2  # ipv4 dedup'd


def test_make_external_reference():
    ref = make_external_reference("Stairwell", "https://app.stairwell.com/x", "desc")
    assert ref["source_name"] == "Stairwell"
    assert ref["url"] == "https://app.stairwell.com/x"
    assert ref["description"] == "desc"
