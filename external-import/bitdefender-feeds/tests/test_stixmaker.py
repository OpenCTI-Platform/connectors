"""STIX conversion tests. Require the connector's pinned runtime dependencies.

Run from the connector directory with: python -m pytest -q tests
Tests use actual stix2 and pycti, but mock the OpenCTI helper/API.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

pycti = pytest.importorskip("pycti")
stix2 = pytest.importorskip("stix2")
pytest.importorskip("iso3166")

from src.bitdefender_import_feed.stixmaker import StixMaker, StixMakerPrivate

BASE = {
    "timestamp": 1700000000,
    "first_seen": 1699999900,
    "confidence": 80,
    "severity": 65,
}


@pytest.fixture
def helper():
    h = MagicMock()
    h.connect_name = "Bitdefender test"
    h.connect_id = "connector-test-id"
    h.api.work.initiate_work.return_value = "work-123"
    h.api.indicator.generate_id_from_data.side_effect = (
        lambda values: pycti.Indicator.generate_id(values["pattern"])
    )
    h.api.malware.generate_id_from_data.side_effect = (
        lambda values: pycti.Malware.generate_id(values["name"])
    )
    return h


def maker(
    helper,
    feedtype,
    *,
    detection=False,
    tlp_level="clear",
    create_malware_objects=True,
    max_bundle_entries=10000
):
    config = SimpleNamespace(
        bitdefender=SimpleNamespace(
            detection=detection,
            tlp_level=tlp_level,
            min_confidence=1,
            min_severity=1,
            create_malware_objects=create_malware_objects,
        )
    )

    return StixMaker(config, helper, feedtype, max_bundle_entries=max_bundle_entries)


def sent_objects(helper, index=-1):
    call = helper.send_stix2_bundle.call_args_list[index]
    return json.loads(call.kwargs["bundle"])["objects"]


def objects_of_type(objects, kind):
    return [obj for obj in objects if obj["type"] == kind]


def check_relationship_references_in_bundle(objects):
    ids = {obj["id"] for obj in objects}
    for relationship in objects_of_type(objects, "relationship"):
        assert relationship["source_ref"] in ids, relationship
        assert relationship["target_ref"] in ids, relationship
        if "created_by_ref" in relationship:
            assert relationship["created_by_ref"] in ids


def test_ip_entry_emits_indicator_observable_and_based_on(helper):
    m = maker(helper, "ip")
    entry = {**BASE, "ip": "192.0.2.5", "format": "IPv4", "type": "IP"}
    assert m.fromEntry(json.dumps(entry)) is False
    m.sendFinal()
    objs = sent_objects(helper)
    assert len(objects_of_type(objs, "ipv4-addr")) == 1
    indicators = objects_of_type(objs, "indicator")
    assert len(indicators) == 1
    assert indicators[0]["x_opencti_detection"] is False
    assert indicators[0]["pattern"] == "[ipv4-addr:value = '192.0.2.5']"
    assert any(
        r["relationship_type"] == "based-on"
        for r in objects_of_type(objs, "relationship")
    )
    check_relationship_references_in_bundle(objs)
    helper.api.work.to_processed.assert_called_once_with("work-123", "done")
    helper.api.work.initiate_work.assert_called_once_with(
        "connector-test-id", "importing ip feed", is_multipart=True
    )


def test_detection_setting_is_respected(helper):
    m = maker(helper, "web", detection=True)
    m.fromEntry(json.dumps({**BASE, "type": "domain", "url": "mal.example"}))
    m.sendFinal()
    indicator = objects_of_type(sent_objects(helper), "indicator")[0]
    assert indicator["x_opencti_detection"] is True


def test_web_domain_and_url_entries(helper):
    m = maker(helper, "web")
    m.fromEntry(json.dumps({**BASE, "type": "domain", "url": "mal.example"}))
    m.fromEntry(json.dumps({**BASE, "type": "url", "url": "https://mal.example/a"}))
    m.sendFinal()
    objects = sent_objects(helper)
    assert len(objects_of_type(objects, "domain-name")) == 1
    assert len(objects_of_type(objects, "url")) == 1
    assert len(objects_of_type(objects, "indicator")) == 2
    check_relationship_references_in_bundle(objects)


def test_file_without_names_or_malware_label_does_not_raise(helper):
    m = maker(helper, "file")
    entry = {
        **BASE,
        "sha256": "a" * 64,
        "file_names": [],
        "threat_family": "example",
        "related_indicators": [],
    }
    m.fromEntry(json.dumps(entry))
    m.sendFinal()
    objects = sent_objects(helper)
    assert len(objects_of_type(objects, "file")) == 1
    assert len(objects_of_type(objects, "indicator")) == 1
    # The family is still retained even without a detection-level Malware object.
    malware = objects_of_type(objects, "malware")
    assert len(malware) == 1 and malware[0]["is_family"] is True
    # Optional metadata may still be ignored, but must not abort the entry.
    check_relationship_references_in_bundle(objects)


def test_file_with_detection_emits_malware_and_indicates(helper):
    m = maker(helper, "file")
    entry = {
        **BASE,
        "sha256": "b" * 64,
        "file_names": ["payload.exe"],
        "threat_label": "Test.Detection",
    }
    m.fromEntry(json.dumps(entry))
    m.sendFinal()
    objects = sent_objects(helper)
    assert len(objects_of_type(objects, "malware")) == 1
    assert any(
        r["relationship_type"] == "indicates"
        for r in objects_of_type(objects, "relationship")
    )
    check_relationship_references_in_bundle(objects)


def test_referenced_countries_and_sectors_are_reincluded_in_each_bundle(helper):
    m = maker(helper, "ip", max_bundle_entries=1)
    for ip in ("192.0.2.11", "192.0.2.12"):
        entry = {
            **BASE,
            "ip": ip,
            "format": "IPv4",
            "affected_countries": [{"country": "BR", "percentage": 3.85}],
            "affected_industries": [{"industry": "Finance", "percentage": 20}],
        }
        assert m.fromEntry(json.dumps(entry)) is True
    assert helper.send_stix2_bundle.call_count == 2
    first, second = sent_objects(helper, 0), sent_objects(helper, 1)
    for objs in (first, second):
        assert len(objects_of_type(objs, "location")) == 1
        # Finance sector + Bitdefender creator
        assert len(objects_of_type(objs, "identity")) == 2
        check_relationship_references_in_bundle(objs)
    first_country = objects_of_type(first, "location")[0]["id"]
    assert objects_of_type(second, "location")[0]["id"] == first_country
    m.sendFinal()
    assert helper.send_stix2_bundle.call_count == 2


def test_mitre_attack_pattern_uses_mitre_id_and_serializes_as_extension(helper):
    m = maker(helper, "web")
    entry = {**BASE, "url": "mal.example", "type": "domain", "mitre_attack": ["T1059"]}
    m.fromEntry(json.dumps(entry))
    m.sendFinal()
    objects = sent_objects(helper)
    attack = objects_of_type(objects, "attack-pattern")[0]
    assert attack["id"] == pycti.AttackPattern.generate_id("T1059", "T1059")
    assert attack["x_mitre_id"] == "T1059"
    check_relationship_references_in_bundle(objects)


def test_unknown_country_does_not_discard_valid_ip(helper):
    m = maker(helper, "ip")
    entry = {
        **BASE,
        "ip": "192.0.2.23",
        "format": "IPv4",
        "affected_countries": [{"country": "NOT-A-COUNTRY", "percentage": 1}],
    }
    m.fromEntry(json.dumps(entry))
    m.sendFinal()
    assert len(objects_of_type(sent_objects(helper), "indicator")) == 1
    helper.connector_logger.warning.assert_called()


def test_unknown_fields_warn_but_do_not_abort(helper):
    m = maker(helper, "web")
    m.fromEntry(
        json.dumps(
            {
                **BASE,
                "type": "domain",
                "url": "mal.example",
                "new_vendor_attribute": {"foo": "bar"},
            }
        )
    )
    m.sendFinal()
    assert len(objects_of_type(sent_objects(helper), "indicator")) == 1
    helper.connector_logger.warning.assert_called()


def test_deterministic_relationship_id_and_explicit_error_closure(helper):
    m = maker(helper, "web")
    m.fromEntry(json.dumps({**BASE, "type": "domain", "url": "mal.example"}))
    m.sendFinal()
    rel = objects_of_type(sent_objects(helper), "relationship")[0]
    assert rel["id"] == pycti.StixCoreRelationship.generate_id(
        rel["relationship_type"], rel["source_ref"], rel["target_ref"]
    )
    helper.api.work.to_processed.reset_mock()
    m.sendError("forced failure")
    helper.api.work.to_processed.assert_called_once_with(
        "work-123", "forced failure", in_error=True
    )


def test_related_file_without_name_keeps_only_hash(helper):
    m = maker(helper, "file")
    related = {
        "relationship": "file_downloads_file",
        "type": "file",
        "sha256": "c" * 64,
    }
    obj, rel = StixMakerPrivate(m)._parseRelatedIndicator(
        related, "file--123e4567-e89b-42d3-a456-426614174000"
    )
    assert obj["type"] == "file"
    assert "name" not in obj
    assert obj["hashes"]["SHA-256"] == "c" * 64
    assert rel["relationship_type"] == "downloads"


# create_malware_objects should trigger creation of indicator


def matching_object(objects, kind, **fields):
    matches = [
        o
        for o in objects_of_type(objects, kind)
        if all(o.get(k) == v for k, v in fields.items())
    ]
    assert len(matches) == 1, (kind, fields, matches)
    return matches[0]


def assert_edge(objects, kind, source, target):
    matches = [
        r
        for r in objects_of_type(objects, "relationship")
        if r["relationship_type"] == kind
        and r["source_ref"] == source["id"]
        and r["target_ref"] == target["id"]
    ]
    assert len(matches) == 1, (kind, source["id"], target["id"], matches)
    return matches[0]


def test_complete_ip_entry_with_attribution_vulnerability_and_related_ip(helper):
    """Real stix2 serialization: endpoints and directions, not only object counts."""
    m = maker(helper, "ip", tlp_level="green")
    entry = {
        **BASE,
        "type": "IP",
        "format": "IPv4",
        "ip": "192.0.2.11",
        "asn": 64512,
        "asn_owner": "Example ASN",
        "flags": ["proxy"],
        "affected_countries": [{"country": "BR", "percentage": 25}],
        "affected_industries": [{"industry": "Finance", "percentage": 20}],
        "actor_name": "Example Actor",
        "mitre_attack": ["T1059"],
        "exploited_vulnerabilities": [
            {"cve_id": "CVE-2024-0001", "cvss_score": {"v2": 5.0, "v3": 7.0}}
        ],
        "related_indicators": [
            {
                "type": "domain",
                "domain": "callback.example",
                "relationship": "ip_is_resolved_from_domain",
            },
        ],
    }
    m.fromEntry(json.dumps(entry))
    m.sendFinal()
    objects = sent_objects(helper)
    ip = matching_object(objects, "ipv4-addr", value="192.0.2.11")
    indicator = matching_object(objects, "indicator", name="192.0.2.11")
    country = matching_object(objects, "location", country="BR")
    sector = matching_object(objects, "identity", name="Finance")
    actor = matching_object(objects, "threat-actor", name="Example Actor")
    vulnerability = matching_object(objects, "vulnerability", name="CVE-2024-0001")
    attack = matching_object(objects, "attack-pattern", name="T1059")
    domain = matching_object(objects, "domain-name", value="callback.example")
    assert_edge(objects, "based-on", indicator, ip)
    assert_edge(objects, "related-to", indicator, country)
    assert_edge(objects, "related-to", indicator, sector)
    assert_edge(objects, "related-to", actor, indicator)
    assert_edge(objects, "targets", actor, country)
    assert_edge(objects, "targets", actor, sector)
    assert_edge(objects, "related-to", indicator, vulnerability)
    assert_edge(objects, "related-to", indicator, attack)
    assert_edge(objects, "resolves-to", domain, ip)
    assert vulnerability["x_opencti_cvss_base_score"] == 7.0
    assert "CVSS v2: 5.0" in vulnerability["description"]
    assert indicator["object_marking_refs"] == [m.tlp.id]
    assert ip["object_marking_refs"] == [m.tlp.id]
    assert all(
        r["object_marking_refs"] == [m.tlp.id]
        for r in objects_of_type(objects, "relationship")
    )
    check_relationship_references_in_bundle(objects)


def test_complete_file_entry_with_family_and_related_observables(helper):
    m = maker(helper, "file")
    hash_value = "a" * 64
    entry = {
        **BASE,
        "type": "file",
        "sha256": hash_value,
        "file_names": ["payload.exe"],
        "threat_label": "Trojan.Generic",
        "threat_family": "testfamily",
        "threat_type": "trojan",
        "affected_countries": [{"country": "MX", "percentage": 30}],
        "related_indicators": [
            {"type": "file", "sha256": "b" * 64, "relationship": "file_downloads_file"},
            {
                "type": "ipv4",
                "ipv4": "203.0.113.3",
                "relationship": "file_connects_to_ip",
            },
        ],
    }
    m.fromEntry(json.dumps(entry))
    m.sendFinal()
    objects = sent_objects(helper)
    file = matching_object(objects, "file", name="payload.exe")
    indicator = matching_object(objects, "indicator", name=hash_value)
    detection = matching_object(objects, "malware", name="Trojan.Generic")
    family = matching_object(objects, "malware", name="Testfamily")
    related = matching_object(objects, "file", hashes={"SHA-256": "b" * 64})
    remote_ip = matching_object(objects, "ipv4-addr", value="203.0.113.3")
    assert_edge(objects, "based-on", indicator, file)
    assert_edge(objects, "indicates", indicator, detection)
    assert_edge(objects, "variant-of", detection, family)
    assert_edge(objects, "downloads", file, related)
    assert_edge(objects, "communicates-with", file, remote_ip)
    check_relationship_references_in_bundle(objects)


def test_family_only_mode_preserves_family_and_related_file_links(helper):
    m = maker(helper, "file", create_malware_objects=False)
    entry = {
        **BASE,
        "sha256": "f" * 64,
        "file_names": [],
        "threat_label": "Generic.Detection",
        "threat_family": "testfamily",
        "related_indicators": [
            {
                "type": "domain",
                "domain": "callback.example",
                "relationship": "file_connects_to_domain",
            },
        ],
    }
    m.fromEntry(json.dumps(entry))
    m.sendFinal()
    objects = sent_objects(helper)
    assert len(objects_of_type(objects, "malware")) == 1
    file = matching_object(objects, "file", hashes={"SHA-256": "f" * 64})
    ioc = matching_object(objects, "indicator", name="f" * 64)
    family = matching_object(objects, "malware", name="Testfamily")
    domain = matching_object(objects, "domain-name", value="callback.example")
    assert "Generic.Detection" in ioc["labels"]
    assert_edge(objects, "indicates", ioc, family)
    assert_edge(objects, "communicates-with", file, domain)
    check_relationship_references_in_bundle(objects)


@pytest.mark.parametrize(
    "type_,value,observable_type",
    [
        ("domain", "evil.example", "domain-name"),
        ("url", "https://evil.example/path", "url"),
    ],
)
def test_complete_web_entry_with_related_ip_and_markings(
    helper, type_, value, observable_type
):
    m = maker(helper, "web", detection=True, tlp_level="green")
    entry = {
        **BASE,
        "type": type_,
        "url": value,
        "threat_types": ["phishing"],
        "flags": ["suspicious"],
        "mitre_attack": ["T1059"],
        "related_indicators": [
            {
                "type": "ipv4",
                "ipv4": "203.0.113.5",
                "relationship": (
                    "domain_resolves_to_ip"
                    if type_ == "domain"
                    else "url_resolves_to_ip"
                ),
            }
        ],
    }
    m.fromEntry(json.dumps(entry))
    m.sendFinal()
    objects = sent_objects(helper)
    observable = matching_object(objects, observable_type, value=value)
    indicator = matching_object(objects, "indicator", name=value)
    ip = matching_object(objects, "ipv4-addr", value="203.0.113.5")
    attack = matching_object(objects, "attack-pattern", name="T1059")
    assert "phishing" in indicator["labels"]
    assert indicator["x_opencti_detection"] is True
    assert "flags:" in indicator["description"]
    assert "x_opencti_flags" not in indicator
    assert_edge(objects, "based-on", indicator, observable)
    assert_edge(objects, "related-to", indicator, attack)
    assert_edge(
        objects, "resolves-to" if type_ == "domain" else "related-to", observable, ip
    )
    assert observable["object_marking_refs"] == [m.tlp.id]
    check_relationship_references_in_bundle(objects)


def test_ipv4_entry_without_optional_format_still_uses_ipv4_observable(helper):
    m = maker(helper, "ip")
    m.fromEntry(json.dumps({**BASE, "type": "IP", "ip": "192.0.2.3"}))
    m.sendFinal()
    objects = sent_objects(helper)
    assert len(objects_of_type(objects, "ipv4-addr")) == 1
    assert len(objects_of_type(objects, "ipv6-addr")) == 0


def test_ip_nested_affected_and_popularity(helper):
    m = maker(helper, "ip")
    m.fromEntry(
        json.dumps(
            {
                **BASE,
                "ip": "192.0.2.4",
                "type": "IP",
                "popularity": 42,
                "affected_countries": [{"country": "BR", "percentage": 3.85}],
                "affected_industries": [{"industry": "Finance", "percentage": 20}],
            }
        )
    )
    m.sendFinal()
    objs = sent_objects(helper)
    indicator = matching_object(objs, "indicator", name="192.0.2.4")
    country = matching_object(objs, "location", country="BR")
    sector = matching_object(objs, "identity", name="Finance")
    assert "popularity: 42" in indicator["description"]
    assert_edge(objs, "related-to", indicator, country)
    assert_edge(objs, "related-to", indicator, sector)
    check_relationship_references_in_bundle(objs)


def test_repeated_asn_is_cached_and_uses_number_based_id(helper):
    m = maker(helper, "ip")
    for address, owner in (
        ("192.0.2.60", "Original Provider"),
        ("192.0.2.61", "Updated Provider"),
    ):
        m.fromEntry(
            json.dumps(
                {**BASE, "type": "IP", "ip": address, "asn": 64512, "asn_owner": owner}
            )
        )
    m.sendFinal()
    objects = sent_objects(helper)
    systems = objects_of_type(objects, "autonomous-system")
    assert len(systems) == 1
    assert systems[0]["id"] == stix2.AutonomousSystem(number=64512).id
    for ip in objects_of_type(objects, "ipv4-addr"):
        assert ip["belongs_to_refs"] == [systems[0]["id"]]
    check_relationship_references_in_bundle(objects)
