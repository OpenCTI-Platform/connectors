"""Offline graph-contract tests for complete Bitdefender IP, file, and web entries.

Uses lightweight stand-ins for stix2/pycti so these tests run even in a
minimal developer environment. These tests verify parser decisions and graph
shape, NOT STIX schema acceptance. test_stixmaker.py runs real stix2/pycti
construction and serialization once the connector dependencies are installed.
"""

import importlib.util
import json
import sys
import types
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

SOURCE = (
    Path(__file__).resolve().parents[1] / "src/bitdefender_import_feed/stixmaker.py"
)
BASE = {
    "timestamp": 1700000000,
    "first_seen": 1699999900,
    "confidence": 80,
    "severity": 65,
}
SHA256 = "a" * 64
SHA1 = "b" * 40
MD5 = "c" * 32


def stable_id(type_, *parts):
    key = ":".join(map(str, parts))
    return f"{type_}--{uuid.uuid5(uuid.NAMESPACE_DNS, key)}"


@pytest.fixture
def runtime(monkeypatch):
    """Import actual parser against strict in-memory substitutes for dependencies."""
    stix = types.ModuleType("stix2")
    pycti = types.ModuleType("pycti")
    iso = types.ModuleType("iso3166")

    class Object(dict):
        def __init__(self, object_type, **values):
            values = dict(values)
            values.pop("allow_custom", None)
            extras = values.pop("custom_properties", {})
            values.update(extras)
            refs = values.get("object_marking_refs")
            if refs is not None and (
                not isinstance(refs, list)
                or not all(isinstance(ref, str) for ref in refs)
            ):
                raise TypeError("object_marking_refs must be a list of STIX IDs")
            if object_type == "relationship":
                for key in ("source_ref", "target_ref", "relationship_type"):
                    if not values.get(key):
                        raise ValueError(f"relationship missing {key}")
            if object_type == "indicator" and not values.get("pattern"):
                raise ValueError("indicator missing pattern")
            if object_type == "file" and not values.get("hashes"):
                raise ValueError("file missing hashes")
            semantic = (
                values.get("value")
                or values.get("pattern")
                or values.get("name")
                or values.get("hashes")
                or values
            )
            values.setdefault(
                "id",
                stable_id(
                    object_type,
                    (
                        json.dumps(semantic, sort_keys=True)
                        if isinstance(semantic, dict)
                        else semantic
                    ),
                ),
            )
            values["type"] = object_type
            super().__init__(values)

        @property
        def id(self):
            return self["id"]

        def serialize(self):
            return json.dumps(dict(self))

    def object_factory(type_):
        return lambda **kwargs: Object(type_, **kwargs)

    for class_name, type_name in (
        ("Indicator", "indicator"),
        ("Identity", "identity"),
        ("Location", "location"),
        ("Malware", "malware"),
        ("AttackPattern", "attack-pattern"),
        ("ThreatActor", "threat-actor"),
        ("Vulnerability", "vulnerability"),
        ("Relationship", "relationship"),
        ("IPv4Address", "ipv4-addr"),
        ("IPv6Address", "ipv6-addr"),
        ("AutonomousSystem", "autonomous-system"),
        ("File", "file"),
        ("DomainName", "domain-name"),
        ("URL", "url"),
        ("MarkingDefinition", "marking-definition"),
    ):
        setattr(stix, class_name, object_factory(type_name))

    class Bundle:
        def __init__(self, objects, **kwargs):
            self.objects = objects

        def serialize(self):
            return json.dumps(
                {"type": "bundle", "objects": [dict(o) for o in self.objects]}
            )

    stix.Bundle = Bundle
    for name in ("WHITE", "GREEN", "AMBER", "RED"):
        setattr(
            stix,
            "TLP_" + name,
            Object(
                "marking-definition",
                id=stable_id("marking-definition", name),
                name="TLP:" + name,
            ),
        )

    def helper_class(type_, key):
        return SimpleNamespace(
            generate_id=lambda *args, **kwargs: stable_id(
                type_,
                (
                    json.dumps(kwargs, sort_keys=True)
                    if kwargs
                    else ":".join(map(str, args))
                ),
            ),
            generate_id_from_data=lambda data: stable_id(type_, data[key]),
        )

    for class_name, type_name, key in (
        ("Indicator", "indicator", "pattern"),
        ("Identity", "identity", "name"),
        ("Location", "location", "name"),
        ("Malware", "malware", "name"),
        ("AttackPattern", "attack-pattern", "name"),
        ("ThreatActor", "threat-actor", "name"),
        ("Vulnerability", "vulnerability", "name"),
        ("StixCoreRelationship", "relationship", "relationship_type"),
        ("MarkingDefinition", "marking-definition", "name"),
    ):
        setattr(pycti, class_name, helper_class(type_name, key))

    iso.countries = {
        "BR": SimpleNamespace(name="Brazil", alpha2="BR", alpha3="BRA"),
        "US": SimpleNamespace(
            name="United States of America", alpha2="US", alpha3="USA"
        ),
        "MX": SimpleNamespace(name="Mexico", alpha2="MX", alpha3="MEX"),
    }

    monkeypatch.setitem(sys.modules, "stix2", stix)
    monkeypatch.setitem(sys.modules, "pycti", pycti)
    monkeypatch.setitem(sys.modules, "iso3166", iso)
    spec = importlib.util.spec_from_file_location("_bd_parser_offline", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    helper = MagicMock()
    helper.connect_name = "Bitdefender test"
    helper.connect_id = "connector-test-id"
    helper.api.work.initiate_work.return_value = "work-123"
    helper.api.indicator.generate_id_from_data.side_effect = (
        pycti.Indicator.generate_id_from_data
    )
    helper.api.malware.generate_id_from_data.side_effect = (
        pycti.Malware.generate_id_from_data
    )

    def create(feed, **settings):
        defaults = {
            "detection": False,
            "tlp_level": "green",
            "create_malware_objects": True,
        }
        defaults.update(settings)
        config = SimpleNamespace(bitdefender=SimpleNamespace(**defaults))
        maker = module.StixMaker(config, helper, feed, max_bundle_entries=10000)
        helper.send_stix2_bundle.reset_mock()
        return maker

    return SimpleNamespace(create=create, helper=helper, pycti=pycti, stix=stix)


def get_objects(runtime, maker, entry):
    assert maker.fromEntry(json.dumps(entry)) is False
    maker.sendFinal()
    payload = runtime.helper.send_stix2_bundle.call_args.kwargs["bundle"]
    return json.loads(payload)["objects"]


def type_objects(objects, type_):
    return [obj for obj in objects if obj["type"] == type_]


def exactly_one(objects, type_, **criteria):
    found = [
        obj
        for obj in type_objects(objects, type_)
        if all(obj.get(k) == v for k, v in criteria.items())
    ]
    assert len(found) == 1, (type_, criteria, found)
    return found[0]


def relationship(objects, kind, source, target):
    found = [
        o
        for o in type_objects(objects, "relationship")
        if o["relationship_type"] == kind
        and o["source_ref"] == source["id"]
        and o["target_ref"] == target["id"]
    ]
    assert len(found) == 1, (kind, source["id"], target["id"], found)
    return found[0]


def check_graph(objects, tlp_id):
    ids = {o["id"] for o in objects}
    assert len(ids) == len(objects), "bundle contains duplicate STIX IDs"
    for obj in objects:
        if "created_by_ref" in obj:
            assert obj["created_by_ref"] in ids, obj
        if "object_marking_refs" in obj:
            assert isinstance(obj["object_marking_refs"], list)
            assert obj["object_marking_refs"] == [tlp_id], obj
    for rel in type_objects(objects, "relationship"):
        assert rel["source_ref"] in ids and rel["target_ref"] in ids, rel
        assert rel["object_marking_refs"] == [tlp_id]


def test_full_ipv4_with_attribution_and_related_observables(runtime):
    m = runtime.create("ip")
    entry = {
        **BASE,
        "type": "IP",
        "format": "IPv4",
        "ip": "192.0.2.10",
        "asn": 64512,
        "asn_owner": "Example ASN",
        "flags": ["proxy"],
        "ports": [443],
        "affected_countries": [{"country": "BR", "percentage": 20}],
        "affected_industries": [{"industry": "Financial Services", "percentage": 10}],
        "actor_name": "Test Actor",
        "mitre_attack": ["T1059"],
        "exploited_vulnerabilities": [
            {"cve_id": "CVE-2024-0001", "cvss_score": {"v3": 7.1}}
        ],
        "related_indicators": [
            {
                "type": "domain",
                "domain": "host.example",
                "relationship": "ip_is_resolved_from_domain",
            },
            {
                "type": "file",
                "sha256": SHA256,
                "relationship": "ip_is_connected_to_by_file",
            },
        ],
    }
    objects = get_objects(runtime, m, entry)
    ip = exactly_one(objects, "ipv4-addr", value="192.0.2.10")
    ioc = exactly_one(objects, "indicator", name="192.0.2.10")
    asn = exactly_one(objects, "autonomous-system", number=64512)
    assert ip["belongs_to_refs"] == [asn["id"]]
    assert "ports: [443]" in ioc["description"]
    assert "flags" not in ioc or "x_opencti_flags" not in ioc
    country = exactly_one(objects, "location", name="Brazil")
    sector = exactly_one(objects, "identity", name="Financial Services")
    actor = exactly_one(objects, "threat-actor", name="Test Actor")
    vuln = exactly_one(objects, "vulnerability", name="CVE-2024-0001")
    pattern = exactly_one(objects, "attack-pattern", name="T1059")
    domain = exactly_one(objects, "domain-name", value="host.example")
    related_file = exactly_one(objects, "file", hashes={"SHA-256": SHA256})
    relationship(objects, "based-on", ioc, ip)
    relationship(objects, "related-to", ioc, country)
    relationship(objects, "related-to", ioc, sector)
    relationship(objects, "related-to", actor, ioc)
    relationship(objects, "targets", actor, country)
    relationship(objects, "targets", actor, sector)
    relationship(objects, "related-to", ioc, vuln)
    relationship(objects, "related-to", ioc, pattern)
    relationship(objects, "resolves-to", domain, ip)
    relationship(objects, "communicates-with", related_file, ip)
    check_graph(objects, m.tlp.id)


def test_ipv6_without_format_is_detected_from_address(runtime):
    m = runtime.create("ip")
    objs = get_objects(runtime, m, {**BASE, "type": "IP", "ip": "2001:db8::1234"})
    ip = exactly_one(objs, "ipv6-addr", value="2001:db8::1234")
    indicator = exactly_one(objs, "indicator", name="2001:db8::1234")
    assert indicator["pattern"] == "[ipv6-addr:value = '2001:db8::1234']"
    relationship(objs, "based-on", indicator, ip)
    check_graph(objs, m.tlp.id)


def test_full_file_entry_links_malware_family_and_related_files(runtime):
    m = runtime.create("file")
    entry = {
        **BASE,
        "type": "file",
        "sha256": SHA256,
        "sha1": SHA1,
        "md5": MD5,
        "file_names": ["sample.exe"],
        "file_size": 12345,
        "threat_label": "Trojan.Generic",
        "threat_family": "examplefamily",
        "threat_type": "trojan",
        "tags": ["banker"],
        "affected_countries": [{"country": "MX", "percentage": 25}],
        "affected_industries": [{"industry": "Retail", "percentage": 15}],
        "actor_name": "Example Threat Actor",
        "mitre_attack": ["T1059"],
        "exploited_vulnerabilities": [{"cve_id": "CVE-2024-0001"}],
        "related_indicators": [
            {"type": "file", "sha256": "f" * 64, "relationship": "file_downloads_file"},
            {
                "type": "ipv4",
                "ipv4": "198.51.100.22",
                "relationship": "file_connects_to_ip",
            },
        ],
    }
    objs = get_objects(runtime, m, entry)
    file = exactly_one(objs, "file", name="sample.exe")
    ioc = exactly_one(objs, "indicator", name=SHA256)
    malware = exactly_one(objs, "malware", name="Trojan.Generic")
    family = exactly_one(objs, "malware", name="Examplefamily")
    assert malware["is_family"] is False and family["is_family"] is True
    assert ioc["pattern"].startswith("[") and "SHA-256" in ioc["pattern"]
    country = exactly_one(objs, "location", name="Mexico")
    sector = exactly_one(objs, "identity", name="Retail")
    actor = exactly_one(objs, "threat-actor", name="Example Threat Actor")
    vuln = exactly_one(objs, "vulnerability", name="CVE-2024-0001")
    pattern = exactly_one(objs, "attack-pattern", name="T1059")
    related_file = exactly_one(objs, "file", hashes={"SHA-256": "f" * 64})
    related_ip = exactly_one(objs, "ipv4-addr", value="198.51.100.22")
    relationship(objs, "based-on", ioc, file)
    relationship(objs, "indicates", ioc, malware)
    relationship(objs, "variant-of", malware, family)
    relationship(objs, "targets", malware, country)
    relationship(objs, "targets", malware, sector)
    relationship(objs, "uses", actor, malware)
    relationship(objs, "targets", actor, country)
    relationship(objs, "targets", actor, sector)
    relationship(objs, "exploits", malware, vuln)
    relationship(objs, "uses", malware, pattern)
    relationship(objs, "downloads", file, related_file)
    relationship(objs, "communicates-with", file, related_ip)
    check_graph(objs, m.tlp.id)


def test_family_only_file_keeps_family_and_related_observables(runtime):
    m = runtime.create("file", create_malware_objects=False)
    objs = get_objects(
        runtime,
        m,
        {
            **BASE,
            "sha256": SHA256,
            "file_names": [],
            "threat_label": "Generic.Detection",
            "threat_family": "familia",
            "related_indicators": [
                {
                    "type": "domain",
                    "domain": "callback.example",
                    "relationship": "file_connects_to_domain",
                }
            ],
        },
    )
    file = exactly_one(objs, "file", hashes={"SHA-256": SHA256})
    ioc = exactly_one(objs, "indicator", name=SHA256)
    family = exactly_one(objs, "malware", name="Familia")
    assert not [o for o in type_objects(objs, "malware") if not o["is_family"]]
    assert "Generic.Detection" in ioc.get("labels", [])
    domain = exactly_one(objs, "domain-name", value="callback.example")
    relationship(objs, "indicates", ioc, family)
    relationship(objs, "communicates-with", file, domain)
    check_graph(objs, m.tlp.id)


@pytest.mark.parametrize(
    "kind,value,expected_type,expected_pattern",
    [
        (
            "domain",
            "evil.example",
            "domain-name",
            "[domain-name:value = 'evil.example']",
        ),
        (
            "url",
            "https://evil.example/download",
            "url",
            "[url:value = 'https://evil.example/download']",
        ),
    ],
)
def test_full_web_entries_and_related_links(
    runtime, kind, value, expected_type, expected_pattern
):
    m = runtime.create("web", detection=True)
    entry = {
        **BASE,
        "type": kind,
        "url": value,
        "threat_types": ["phishing"],
        "flags": ["suspicious"],
        "affected_countries": [{"country": "US", "percentage": 12}],
        "mitre_attack": ["T1059"],
        "related_indicators": [
            {
                "type": "ipv4",
                "ipv4": "203.0.113.19",
                "relationship": (
                    "domain_resolves_to_ip"
                    if kind == "domain"
                    else "url_resolves_to_ip"
                ),
            }
        ],
    }
    objs = get_objects(runtime, m, entry)
    observable = exactly_one(objs, expected_type, value=value)
    indicator = exactly_one(objs, "indicator", name=value)
    related_ip = exactly_one(objs, "ipv4-addr", value="203.0.113.19")
    country = exactly_one(objs, "location", name="United States of America")
    pattern = exactly_one(objs, "attack-pattern", name="T1059")
    assert indicator["pattern"] == expected_pattern
    assert indicator["x_opencti_detection"] is True
    assert "phishing" in indicator["labels"]
    assert "flags:" in indicator["description"]
    assert "x_opencti_flags" not in indicator
    relationship(objs, "based-on", indicator, observable)
    relationship(objs, "related-to", indicator, country)
    relationship(objs, "related-to", indicator, pattern)
    relationship(
        objs,
        "resolves-to" if kind == "domain" else "related-to",
        observable,
        related_ip,
    )
    check_graph(objs, m.tlp.id)


def test_explicit_false_revoked_does_not_revoke_indicator(runtime):
    m = runtime.create("web")
    objs = get_objects(
        runtime, m, {**BASE, "type": "domain", "url": "live.example", "revoked": False}
    )
    assert exactly_one(objs, "indicator")["revoked"] is False


def test_nested_victims_from_ip_feed_snapshot_are_not_dropped(runtime):
    m = runtime.create("ip")
    objects = get_objects(
        runtime,
        m,
        {
            **BASE,
            "ip": "192.0.2.77",
            "type": "IP",
            "popularity": 42,
            "victims": {
                "countries": [{"country": "BR", "percentage": 3.85}],
                "industries": [{"industry": "Financial-services", "percentage": 20}],
            },
        },
    )
    indicator = exactly_one(objects, "indicator", name="192.0.2.77")
    country = exactly_one(objects, "location", name="Brazil")
    sector = exactly_one(objects, "identity", name="Financial-services")
    relationship(objects, "related-to", indicator, country)
    relationship(objects, "related-to", indicator, sector)
    assert "popularity: 42" in indicator["description"]
    check_graph(objects, m.tlp.id)


def test_unknown_country_warns_without_losing_other_relationships(runtime):
    m = runtime.create("web")
    objects = get_objects(
        runtime,
        m,
        {
            **BASE,
            "type": "domain",
            "url": "sample.example",
            "affected_countries": [
                {"country": "INVALID", "percentage": 1},
                {"country": "BR", "percentage": 2},
            ],
        },
    )
    indicator = exactly_one(objects, "indicator", name="sample.example")
    brazil = exactly_one(objects, "location", name="Brazil")
    relationship(objects, "related-to", indicator, brazil)
    runtime.helper.connector_logger.warning.assert_called()


def test_shared_country_and_identity_reemitted_in_later_bundle(runtime):
    m = runtime.create("ip")
    m.max_bundle_entries = 1
    snapshots = []
    for address in ("192.0.2.100", "192.0.2.101"):
        assert (
            m.fromEntry(
                json.dumps(
                    {
                        **BASE,
                        "ip": address,
                        "type": "IP",
                        "affected_countries": [{"country": "BR", "percentage": 5}],
                        "affected_industries": [
                            {"industry": "Retail", "percentage": 10}
                        ],
                    }
                )
            )
            is True
        )
        snapshots.append(
            json.loads(runtime.helper.send_stix2_bundle.call_args.kwargs["bundle"])[
                "objects"
            ]
        )
    for objects in snapshots:
        country = exactly_one(objects, "location", name="Brazil")
        sector = exactly_one(objects, "identity", name="Retail")
        indicator = exactly_one(objects, "indicator")
        relationship(objects, "related-to", indicator, country)
        relationship(objects, "related-to", indicator, sector)
        check_graph(objects, m.tlp.id)
    assert (
        exactly_one(snapshots[0], "location")["id"]
        == exactly_one(snapshots[1], "location")["id"]
    )
    assert runtime.helper.send_stix2_bundle.call_count == 2


def test_amber_strict_custom_marking_has_opencti_fields(runtime):
    m = runtime.create("web", tlp_level="amber+strict")
    assert m.tlp["x_opencti_definition_type"] == "TLP"
    assert m.tlp["x_opencti_definition"] == "TLP:AMBER+STRICT"
    objects = get_objects(runtime, m, {**BASE, "type": "domain", "url": "example.test"})
    check_graph(objects, m.tlp.id)
