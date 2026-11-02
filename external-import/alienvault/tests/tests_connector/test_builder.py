"""Tests for the pulse bundle builder."""

import json
from datetime import datetime, timezone
from typing import Any, Callable, List, Set, Tuple

import stix2
from alienvault.builder import PulseBundleBuilder, PulseBundleBuilderConfig
from alienvault.models import Pulse, PulseIndicator
from alienvault.utils import create_organization
from pycti import IntrusionSet

CREATED = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
DUMMY_OBJECT_NAME = "AV EMPTY REPORT"


def make_pulse_indicator(indicator_type: str, indicator: str) -> PulseIndicator:
    """Build a pulse indicator with every required field."""
    return PulseIndicator(
        id=1,
        type=indicator_type,
        title="",
        indicator=indicator,
        description="",
        created=CREATED,
        is_active=True,
        content="",
        role=None,
        access_reason=None,
        access_groups=None,
        expiration=None,
    )


def make_builder(pulse: Pulse) -> PulseBundleBuilder:
    """Build a PulseBundleBuilder with a fully filled configuration."""
    config = PulseBundleBuilderConfig(
        pulse=pulse,
        provider=create_organization("AlienVault"),
        source_name="AlienVault",
        object_markings=[stix2.TLP_WHITE],
        create_observables=True,
        create_indicators=True,
        confidence_level=50,
        report_status=0,
        report_type="threat-report",
        guessed_malwares={},
        guessed_cves=set(),
        excluded_pulse_indicator_types=set(),
        enable_relationships=True,
        enable_attack_patterns_indicates=True,
        x_opencti_score=50,
        x_opencti_score_ip=60,
        x_opencti_score_domain=60,
        x_opencti_score_hostname=60,
        x_opencti_score_email=60,
        x_opencti_score_file=60,
        x_opencti_score_url=60,
        x_opencti_score_mutex=60,
        x_opencti_score_cryptocurrency_wallet=60,
    )
    return PulseBundleBuilder(config)


def build_objects(pulse: Pulse) -> List[Any]:
    """Build the bundle of a pulse and return its objects."""
    return list(make_builder(pulse).build().objects)


def objects_of_type(objects: List[Any], stix_type: str) -> List[Any]:
    """Filter bundle objects by STIX type."""
    return [obj for obj in objects if obj["type"] == stix_type]


def relationship_triples(objects: List[Any]) -> Set[Tuple[str, str, str]]:
    """Relationships as (type, source_ref, target_ref) triples."""
    return {
        (rel["relationship_type"], rel["source_ref"], rel["target_ref"])
        for rel in objects_of_type(objects, "relationship")
    }


def assert_references_resolve(objects: List[Any]) -> None:
    """Assert every *_ref and *_refs value points at an object of the bundle."""
    serialized = [json.loads(obj.serialize()) for obj in objects]
    bundle_ids = {obj["id"] for obj in serialized}

    checked = 0
    for obj in serialized:
        for key, value in obj.items():
            if not key.endswith(("_ref", "_refs")):
                continue

            refs = value if isinstance(value, list) else [value]
            for ref in refs:
                assert ref in bundle_ids, f"{obj['id']}.{key} -> {ref}"
                checked += 1
    assert checked


def test_comma_separated_adversary_creates_one_intrusion_set_per_name(
    make_pulse: Callable[..., Pulse],
):
    """#5005: three comma-separated groups give three intrusion sets, not one."""
    objects = build_objects(
        make_pulse(adversary="Linen Typhoon, Storm-2603, Violet Typhoon")
    )

    intrusion_sets = objects_of_type(objects, "intrusion-set")

    assert [i["name"] for i in intrusion_sets] == [
        "Linen Typhoon",
        "Storm-2603",
        "Violet Typhoon",
    ]
    assert [i["id"] for i in intrusion_sets] == [
        IntrusionSet.generate_id("Linen Typhoon"),
        IntrusionSet.generate_id("Storm-2603"),
        IntrusionSet.generate_id("Violet Typhoon"),
    ]


def test_each_intrusion_set_is_linked_like_a_single_adversary(
    make_pulse: Callable[..., Pulse],
):
    """#5005: every split intrusion set gets uses, targets and indicates links."""
    pulse = make_pulse(
        adversary="Linen Typhoon, Storm-2603",
        malware_families=["X-Agent"],
        attack_ids=["T1566"],
        industries=["Government"],
        targeted_countries=["France"],
        indicators=[
            make_pulse_indicator("IPv4", "198.51.100.7"),
            make_pulse_indicator("CVE", "CVE-2024-0001"),
        ],
    )
    objects = build_objects(pulse)

    triples = relationship_triples(objects)
    report = objects_of_type(objects, "report")[0]
    indicator_id = objects_of_type(objects, "indicator")[0]["id"]
    malware_id = objects_of_type(objects, "malware")[0]["id"]
    attack_pattern_id = objects_of_type(objects, "attack-pattern")[0]["id"]
    sector_id = [
        o["id"]
        for o in objects_of_type(objects, "identity")
        if o["identity_class"] == "class"
    ][0]
    country_id = objects_of_type(objects, "location")[0]["id"]
    vulnerability_id = objects_of_type(objects, "vulnerability")[0]["id"]

    for name in ("Linen Typhoon", "Storm-2603"):
        intrusion_set_id = IntrusionSet.generate_id(name)
        assert ("uses", intrusion_set_id, malware_id) in triples
        assert ("uses", intrusion_set_id, attack_pattern_id) in triples
        assert ("targets", intrusion_set_id, sector_id) in triples
        assert ("targets", intrusion_set_id, country_id) in triples
        assert ("targets", intrusion_set_id, vulnerability_id) in triples
        assert ("indicates", indicator_id, intrusion_set_id) in triples
        assert intrusion_set_id in report["object_refs"]

    # Every relationship is part of the report.
    for rel in objects_of_type(objects, "relationship"):
        assert rel["id"] in report["object_refs"]

    # No dangling reference (author, markings, relationship ends, report).
    assert_references_resolve(objects)


def test_single_adversary_keeps_its_previous_intrusion_set_id(
    make_pulse: Callable[..., Pulse],
):
    """#5005: a single adversary has the same id as before the fix."""
    objects = build_objects(make_pulse(adversary="APT28"))

    intrusion_sets = objects_of_type(objects, "intrusion-set")

    assert len(intrusion_sets) == 1
    assert intrusion_sets[0]["name"] == "APT28"
    # Literal produced by the unmodified builder at f30ad5c3e9.
    assert intrusion_sets[0]["id"] == (
        "intrusion-set--f743ab1d-b2f2-58f8-975f-0993511c0b9d"
    )


def test_pulse_without_adversary_has_no_intrusion_set(
    make_pulse: Callable[..., Pulse],
):
    """#5005: no adversary gives no intrusion set, the dummy object keeps the report."""
    objects = build_objects(make_pulse(adversary=None))

    dummy_objects = [
        o
        for o in objects_of_type(objects, "identity")
        if o["name"] == DUMMY_OBJECT_NAME
    ]
    report = objects_of_type(objects, "report")[0]

    assert not objects_of_type(objects, "intrusion-set")
    assert len(dummy_objects) == 1
    assert report["object_refs"] == [dummy_objects[0]["id"]]
    assert_references_resolve(objects)


def test_building_the_same_pulse_twice_gives_identical_ids(
    make_pulse: Callable[..., Pulse],
):
    """#5005: intrusion set and relationship ids are stable across builds."""
    pulse = make_pulse(
        adversary="Linen Typhoon, Storm-2603",
        malware_families=["X-Agent"],
        attack_ids=["T1566"],
    )

    first = build_objects(pulse)
    second = build_objects(pulse)

    for stix_type in ("intrusion-set", "relationship"):
        first_ids = [o["id"] for o in objects_of_type(first, stix_type)]
        second_ids = [o["id"] for o in objects_of_type(second, stix_type)]
        assert first_ids
        assert first_ids == second_ids
