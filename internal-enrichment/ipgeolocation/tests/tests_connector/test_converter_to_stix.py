"""Tests for the STIX conversion."""

import copy

from ipgeolocation_client.models import IPIntelligence
from mock_responses import MOCK_IPGEO_FULL
from pycti import STIX_EXT_OCTI_SCO, Identity, Location, StixCoreRelationship

IPV4_ID = "ipv4-addr--cb5a2f2e-6b3a-5d8a-9a8c-5f2a4e1f9c11"


def _entity(value="2.56.188.34", stix_type="ipv4-addr", entity_id=IPV4_ID):
    return {"type": stix_type, "id": entity_id, "value": value, "spec_version": "2.1"}


def _by_type(objects, stix_type):
    return [o for o in objects if o["type"] == stix_type]


def _relationships(objects):
    return {
        (o["source_ref"].split("--")[0], o["relationship_type"], o["target_ref"])
        for o in _by_type(objects, "relationship")
    }


def test_ids_are_the_ones_opencti_generates(high_risk_intel, scorer, converter):
    objects = converter.build(
        high_risk_intel, scorer.assess(high_risk_intel), _entity()
    )

    locations = {o["x_opencti_location_type"]: o for o in _by_type(objects, "location")}
    assert locations["Country"]["id"] == Location.generate_id(
        "United States", "Country"
    )
    assert locations["City"]["id"] == Location.generate_id("Dallas", "City")
    organizations = {o["name"]: o["id"] for o in _by_type(objects, "identity")}
    assert organizations["Google LLC"] == Identity.generate_id(
        "Google LLC", "organization"
    )
    for relationship in _by_type(objects, "relationship"):
        assert relationship["id"] == StixCoreRelationship.generate_id(
            relationship["relationship_type"],
            relationship["source_ref"],
            relationship["target_ref"],
        )


def test_same_input_gives_the_same_objects(high_risk_intel, scorer, converter):
    risk = scorer.assess(high_risk_intel)
    first = converter.build(high_risk_intel, risk, _entity())
    second = converter.build(high_risk_intel, risk, _entity())

    assert sorted(o["id"] for o in first) == sorted(o["id"] for o in second)


def test_relationships_point_the_right_way(high_risk_intel, scorer, converter):
    objects = converter.build(
        high_risk_intel, scorer.assess(high_risk_intel), _entity()
    )
    country = Location.generate_id("United States", "Country")
    city = Location.generate_id("Dallas", "City")
    relationships = _relationships(objects)

    assert ("ipv4-addr", "located-at", country) in relationships
    assert ("ipv4-addr", "located-at", city) in relationships
    assert ("location", "located-at", country) in relationships
    assert ("hostname", "resolves-to", IPV4_ID) in relationships
    assert ("indicator", "based-on", IPV4_ID) in relationships
    assert any(r[:2] == ("ipv4-addr", "belongs-to") for r in relationships)


def test_every_new_object_has_the_author_and_marking(
    high_risk_intel, scorer, converter
):
    objects = converter.build(
        high_risk_intel, scorer.assess(high_risk_intel), _entity()
    )
    author = next(o for o in objects if o.get("name") == "IPGeolocation.io")
    marking = _by_type(objects, "marking-definition")[0]

    for obj in objects:
        if obj["id"] in (author["id"], marking["id"]):
            continue
        assert (
            obj.get("created_by_ref") == author["id"]
            or obj.get("x_opencti_created_by_ref") == author["id"]
        ), obj["type"]


def test_observable_gets_score_labels_and_reference(high_risk_intel, scorer, converter):
    entity = _entity()
    risk = scorer.assess(high_risk_intel)
    converter.build(high_risk_intel, risk, entity)

    extension = entity["extensions"][STIX_EXT_OCTI_SCO]
    assert extension["score"] == risk.opencti_score
    assert {"vpn", "proxy", "known-attacker", f"risk:{risk.risk_level.lower()}"} <= set(
        extension["labels"]
    )
    assert extension["external_references"][0]["url"].endswith("/2.56.188.34")
    assert "object_marking_refs" not in entity  # the observable keeps its own markings


def test_indicator_for_risky_ipv6(scorer, converter):
    data = copy.deepcopy(MOCK_IPGEO_FULL)
    data["ip"] = "2001:db8::1"
    intel = IPIntelligence.from_ipgeo_response(data)
    entity = _entity(
        "2001:db8::1", "ipv6-addr", "ipv6-addr--0d4c5a4e-1f2b-5c3d-8e9f-0a1b2c3d4e5f"
    )

    objects = converter.build(intel, scorer.assess(intel), entity)

    indicator = _by_type(objects, "indicator")[0]
    assert indicator["pattern"] == "[ipv6-addr:value = '2001:db8::1']"
    assert indicator["x_opencti_main_observable_type"] == "IPv6-Addr"
    assert indicator["name"] == "2001:db8::1"


def test_no_indicator_below_threshold(clean_intel, scorer, converter):
    risk = scorer.assess(clean_intel)
    objects = converter.build(
        clean_intel, risk, _entity("8.8.8.8"), indicator_threshold=50
    )

    assert risk.unified_score < 50
    assert _by_type(objects, "indicator") == []


def test_without_security_data_there_is_no_score_or_indicator(converter):
    data = {k: v for k, v in MOCK_IPGEO_FULL.items() if k not in ("security", "abuse")}
    intel = IPIntelligence.from_ipgeo_response(data)
    entity = _entity()

    objects = converter.build(intel, None, entity, indicator_threshold=0)

    extension = entity["extensions"][STIX_EXT_OCTI_SCO]
    assert "score" not in extension
    assert not any(label.startswith("risk:") for label in extension.get("labels", []))
    assert _by_type(objects, "indicator") == []
    assert _by_type(objects, "location")  # location and ASN still come through


def test_hostname_equal_to_the_ip_is_skipped(clean_intel, scorer, converter):
    clean_intel.hostname = clean_intel.ip
    objects = converter.build(
        clean_intel, scorer.assess(clean_intel), _entity("8.8.8.8")
    )

    assert _by_type(objects, "hostname") == []


def test_features_can_be_turned_off(high_risk_intel, scorer, converter):
    entity = _entity()
    objects = converter.build(
        high_risk_intel,
        scorer.assess(high_risk_intel),
        entity,
        create_labels=False,
        create_relationships=False,
        create_indicator=False,
        create_note=False,
    )

    assert {o["type"] for o in objects} >= {"location", "identity", "autonomous-system"}
    assert not {"relationship", "indicator", "note"} & {o["type"] for o in objects}
    assert "labels" not in entity["extensions"][STIX_EXT_OCTI_SCO]


def test_an_ip_returned_as_hostname_in_another_notation_is_skipped(scorer, converter):
    """Without reverse DNS the API returns the address, e.g. a compressed IPv6."""
    data = copy.deepcopy(MOCK_IPGEO_FULL)
    data["ip"] = "2001:4860:4860:0:0:0:0:8888"
    data["hostname"] = "2001:4860:4860::8888"
    intel = IPIntelligence.from_ipgeo_response(data)
    entity = _entity(
        "2001:4860:4860::8888",
        "ipv6-addr",
        "ipv6-addr--0d4c5a4e-1f2b-5c3d-8e9f-0a1b2c3d4e5f",
    )

    objects = converter.build(intel, scorer.assess(intel), entity)

    assert _by_type(objects, "hostname") == []
    assert not any(o.get("relationship_type") == "resolves-to" for o in objects)
