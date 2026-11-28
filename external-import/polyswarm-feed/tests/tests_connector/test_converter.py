from collections import Counter
from datetime import datetime, timezone

import pytest
from conftest import make_sample_bundle
from connector.connector import build_author, build_tlp_marking
from connector.converter import FeedConverter
from pycti import Identity, Indicator

NOW = datetime(2026, 11, 10, 15, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def author():
    return build_author()


@pytest.fixture
def marking():
    return build_tlp_marking("amber")


@pytest.fixture
def converter(author, marking, fake_logger):
    return FeedConverter(
        author=author,
        tlp_marking=marking,
        indicator_valid_days=90,
        logger=fake_logger,
        now=NOW,
    )


def by_type(objects):
    return Counter(obj["type"] for obj in objects)


def test_author_is_the_shared_polyswarm_organization(author):
    assert author["id"] == Identity.generate_id(
        name="PolySwarm", identity_class="organization"
    )
    assert author["identity_class"] == "organization"


def test_flattens_per_sample_bundles(converter):
    objects = converter.convert_page(
        [make_sample_bundle(1), make_sample_bundle(2, with_attack_pattern=True)]
    )

    counts = by_type(objects)
    assert counts["malware"] == 4
    assert counts["file"] == 2
    assert counts["indicator"] == 6
    assert counts["malware-analysis"] == 4
    assert counts["attack-pattern"] == 1
    assert "bundle" not in counts
    assert len({obj["id"] for obj in objects}) == len(objects)


def test_keeps_polyswarm_ids(converter):
    sample = make_sample_bundle(1)
    # Everything keeps its id, except the indicators sharing one id and the
    # relationships pointing at them (see the rewiring tests below), and the
    # analysis relationships OpenCTI stores as sample_ref instead, and the
    # variant-of between same-named malware.
    original_ids = {
        obj["id"]
        for obj in sample["objects"]
        if obj["type"] != "indicator"
        and not obj.get("source_ref", "").startswith("indicator--")
        and obj.get("relationship_type")
        not in ("av-analysis-of", "dynamic-analysis-of", "variant-of")
    }
    converted_ids = {obj["id"] for obj in converter.convert_item(sample)}
    assert original_ids <= converted_ids


def test_sets_author_and_marking_on_every_object(converter, author, marking):
    objects = converter.convert_page([make_sample_bundle(1, with_attack_pattern=True)])
    assert objects
    for obj in objects:
        assert obj["created_by_ref"] == author["id"]
        assert obj["object_marking_refs"] == [marking["id"]]


def test_tlp_clear_marking_uses_opencti_id():
    marking = build_tlp_marking("clear")
    assert marking["x_opencti_definition"] == "TLP:CLEAR"
    assert marking["id"].startswith("marking-definition--")


def test_indicators_sharing_an_id_get_one_id_per_pattern(converter):
    objects = converter.convert_item(make_sample_bundle(1))
    indicators = [obj for obj in objects if obj["type"] == "indicator"]

    assert len(indicators) == 3
    for indicator in indicators:
        assert indicator["id"] == Indicator.generate_id(indicator["pattern"])
        assert indicator["x_opencti_main_observable_type"] == "StixFile"


def test_relationships_to_shared_indicator_id_are_rewired(converter):
    objects = converter.convert_item(make_sample_bundle(1))
    ids = {obj["id"] for obj in objects}
    indicator_ids = {obj["id"] for obj in objects if obj["type"] == "indicator"}
    indicates = [
        obj
        for obj in objects
        if obj["type"] == "relationship" and obj["relationship_type"] == "indicates"
    ]

    assert {rel["source_ref"] for rel in indicates} == indicator_ids
    assert len(indicates) == 3
    for obj in objects:
        if obj["type"] == "relationship":
            assert obj["source_ref"] in ids and obj["target_ref"] in ids


def test_dangling_references_are_dropped(converter, fake_logger):
    sample = make_sample_bundle(1, with_dynamic_analysis=True)
    sample["objects"].append(
        {
            "type": "relationship",
            "id": "relationship--11111111-1111-4111-8111-111111111111",
            "relationship_type": "related-to",
            "source_ref": "malware--99999999-9999-4999-8999-999999999999",
            "target_ref": sample["objects"][0]["id"],
        }
    )
    objects = converter.convert_item(sample)

    assert "relationship--11111111-1111-4111-8111-111111111111" not in {
        obj["id"] for obj in objects
    }
    dynamic = next(obj for obj in objects if obj.get("product") == "cape")
    assert dynamic["analysis_sco_refs"] == [
        next(obj["id"] for obj in objects if obj["type"] == "file")
    ]
    dropped_logs = [
        meta
        for level, message, meta in fake_logger.records
        if level == "debug" and message.startswith("Dropped references")
    ]
    assert dropped_logs == [
        {"object_id": dynamic["id"], "property": "analysis_sco_refs", "dropped": 1}
    ]


def test_ref_list_emptied_by_filtering_is_removed(converter):
    sample = make_sample_bundle(1, with_dynamic_analysis=True)
    dynamic = next(o for o in sample["objects"] if o.get("product") == "cape")
    dynamic["analysis_sco_refs"] = ["ipv4-addr--a5c97d84-64d1-512b-9be8-3c30d74926ad"]
    converted = next(
        o for o in converter.convert_item(sample) if o.get("product") == "cape"
    )
    assert "analysis_sco_refs" not in converted


def test_valid_until_is_import_time_plus_valid_days(converter):
    objects = converter.convert_item(make_sample_bundle(1))
    for indicator in (obj for obj in objects if obj["type"] == "indicator"):
        assert indicator["valid_until"] == "2027-02-08T15:00:00.000000Z"


def test_valid_until_is_never_before_valid_from(author, marking, fake_logger):
    converter = FeedConverter(author, marking, 1, fake_logger, now=NOW)
    sample = make_sample_bundle(1, created="2027-06-01T00:00:00Z")

    for indicator in (
        obj for obj in converter.convert_item(sample) if obj["type"] == "indicator"
    ):
        assert indicator["valid_until"] == "2027-06-02T00:00:00.000000Z"
        assert indicator["valid_until"] > indicator["valid_from"]


def test_valid_until_overrides_an_already_expired_value(converter):
    sample = make_sample_bundle(1)
    for obj in sample["objects"]:
        if obj["type"] == "indicator":
            obj["valid_until"] = "2020-01-01T00:00:00Z"
    for obj in converter.convert_item(sample):
        if obj["type"] == "indicator":
            assert obj["valid_until"] == "2027-02-08T15:00:00.000000Z"


def test_duplicates_are_dropped_within_a_run(converter):
    first = converter.convert_page([make_sample_bundle(1, with_attack_pattern=True)])
    second = converter.convert_page(
        [
            make_sample_bundle(1, with_attack_pattern=True),
            make_sample_bundle(2, with_attack_pattern=True),
        ]
    )

    first_ids = {obj["id"] for obj in first}
    second_ids = [obj["id"] for obj in second]
    assert len(second_ids) == len(set(second_ids))
    sample_one_only = first_ids - {
        "attack-pattern--4f9fc466-c8f0-5d6c-85f3-095820a41b7b"
    }
    assert not sample_one_only & set(second_ids)


def test_referenced_objects_from_earlier_pages_are_carried(converter):
    converter.convert_page([make_sample_bundle(1, with_attack_pattern=True)])
    second = converter.convert_page([make_sample_bundle(2, with_attack_pattern=True)])

    ids = {obj["id"] for obj in second}
    assert "attack-pattern--4f9fc466-c8f0-5d6c-85f3-095820a41b7b" in ids
    for obj in second:
        if obj["type"] == "relationship":
            assert obj["source_ref"] in ids and obj["target_ref"] in ids


def test_duplicates_inside_one_page_are_dropped(converter):
    objects = converter.convert_page([make_sample_bundle(1), make_sample_bundle(1)])
    assert len(objects) == len({obj["id"] for obj in objects})


@pytest.mark.parametrize(
    "bad_item",
    [
        "not an object",
        None,
        42,
        {"type": "bundle", "objects": "nope"},
        {"no": "type"},
        {"type": "malware", "id": "indicator--wrong-prefix"},
    ],
)
def test_malformed_items_are_skipped_and_logged(converter, fake_logger, bad_item):
    objects = converter.convert_page([bad_item, make_sample_bundle(1)])

    assert converter.skipped_items == 1
    assert any("malformed" in message for message in fake_logger.messages("warning"))
    assert by_type(objects)["file"] == 1


def test_invalid_objects_inside_a_bundle_are_skipped(converter):
    sample = make_sample_bundle(1)
    sample["objects"].extend(
        [None, "x", {"type": "malware"}, {"id": "malware--1"}, {"type": "bundle"}]
    )
    objects = converter.convert_item(sample)
    assert all(isinstance(obj, dict) and obj.get("id") for obj in objects)
    assert converter.skipped_items == 0


def test_plain_stix_object_item_is_accepted(converter):
    item = {
        "type": "attack-pattern",
        "id": "attack-pattern--4f9fc466-c8f0-5d6c-85f3-095820a41b7b",
        "name": "T",
    }
    assert [obj["id"] for obj in converter.convert_page([item])] == [item["id"]]


def test_input_is_not_mutated(converter):
    sample = make_sample_bundle(1)
    before = repr(sample)
    converter.convert_item(sample)
    assert repr(sample) == before
