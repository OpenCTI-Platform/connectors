"""Feed filters: families, excluded families and minimum malware confidence."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from conftest import make_sample_bundle, make_settings
from connector.connector import build_author, build_tlp_marking
from connector.converter import FeedConverter
from connectors_sdk import ConfigValidationError
from test_connector import build, page

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
NOW = datetime(2026, 11, 10, 15, 0, 0, tzinfo=timezone.utc)


def make_converter(fake_logger, **filters):
    return FeedConverter(
        author=build_author(),
        tlp_marking=build_tlp_marking("clear"),
        indicator_valid_days=90,
        logger=fake_logger,
        now=NOW,
        **filters,
    )


def families_of(objects):
    return {o["name"] for o in objects if o["type"] == "malware"}


def samples():
    return [
        make_sample_bundle(1, family="Socks", confidence=99),
        make_sample_bundle(2, family="VBClone", confidence=60),
        make_sample_bundle(3, family="Mole", confidence=47),
    ]


def test_no_filters_keep_everything(fake_logger):
    converter = make_converter(fake_logger)
    objects = converter.convert_page(samples())
    assert families_of(objects) == {"Socks", "VBClone", "Mole"}
    assert converter.filtered_items == 0


def test_families_keeps_only_listed_case_insensitive(fake_logger):
    converter = make_converter(fake_logger, families=["socks", " MOLE "])
    objects = converter.convert_page(samples())
    assert families_of(objects) == {"Socks", "Mole"}
    assert converter.filtered_items == 1


def test_exclude_families_drops_listed(fake_logger):
    converter = make_converter(fake_logger, exclude_families=["vbclone"])
    objects = converter.convert_page(samples())
    assert families_of(objects) == {"Socks", "Mole"}
    assert converter.filtered_items == 1


def test_exclude_wins_over_include(fake_logger):
    converter = make_converter(
        fake_logger, families=["Socks", "Mole"], exclude_families=["Mole"]
    )
    assert families_of(converter.convert_page(samples())) == {"Socks"}


def test_min_confidence_skips_lower(fake_logger):
    converter = make_converter(fake_logger, min_confidence=60)
    objects = converter.convert_page(samples())
    assert families_of(objects) == {"Socks", "VBClone"}
    assert converter.filtered_items == 1


def test_min_confidence_keeps_samples_without_confidence(fake_logger):
    converter = make_converter(fake_logger, min_confidence=90)
    objects = converter.convert_page([make_sample_bundle(1, confidence=None)])
    assert families_of(objects) == {"Socks"}
    assert converter.filtered_items == 0


def test_filters_combine(fake_logger):
    converter = make_converter(
        fake_logger, families=["Socks", "Mole"], min_confidence=50
    )
    assert families_of(converter.convert_page(samples())) == {"Socks"}
    assert converter.filtered_items == 2


def test_filtered_sample_emits_no_object_of_the_sample(fake_logger):
    converter = make_converter(fake_logger, families=["nothing"])
    assert converter.convert_page(samples()) == []
    assert converter.skipped_items == 0
    assert converter.filtered_items == 3


def test_filtered_sample_is_not_malformed(fake_logger):
    converter = make_converter(fake_logger, families=["Socks"])
    assert converter.convert_item(make_sample_bundle(2, family="Mole")) == []
    assert not fake_logger.messages("warning")


@pytest.mark.parametrize(
    "name, kept",
    [
        ("taxii_objects_trustgroup_page1.json", {"Socks", "VBClone"}),
        ("taxii_objects_ransomware_page1.json", {"Mole"}),
        ("taxii_objects_freemium_page1.json", {"AsyncRat", "Outbreak"}),
    ],
)
def test_recorded_pages_unfiltered(fake_logger, name, kept):
    items = json.loads((FIXTURES / name).read_text())["objects"]
    converter = make_converter(fake_logger)
    assert families_of(converter.convert_page(items)) == kept


def test_recorded_freemium_family_filter(fake_logger):
    items = json.loads((FIXTURES / "taxii_objects_freemium_page1.json").read_text())[
        "objects"
    ]
    converter = make_converter(fake_logger, families=["asyncrat"])
    objects = converter.convert_page(items)
    assert families_of(objects) == {"AsyncRat"}
    assert converter.filtered_items == 1
    # The attack pattern belonged to the filtered sample or the kept one, but
    # never dangles: every reference resolves inside the output.
    ids = {o["id"] for o in objects}
    for obj in objects:
        if obj["type"] == "relationship":
            assert obj["source_ref"] in ids and obj["target_ref"] in ids


def test_recorded_ransomware_confidence_filter(fake_logger):
    items = json.loads((FIXTURES / "taxii_objects_ransomware_page1.json").read_text())[
        "objects"
    ]
    # The recorded Mole samples carry a malware confidence of 47.
    assert make_converter(fake_logger, min_confidence=47).convert_page(items)
    converter = make_converter(fake_logger, min_confidence=48)
    assert converter.convert_page(items) == []
    assert converter.filtered_items == len(items)


# ----------------------------------------------------------------------
# Through the connector
# ----------------------------------------------------------------------


def test_connector_passes_settings_to_converter(fake_logger):
    pages = {
        "trustgroup": [
            page(*samples(), last="T1"),
        ]
    }
    connector, helper, _ = build(
        fake_logger,
        pages,
        feed_families="Socks,Mole",
        feed_exclude_families="Mole",
        feed_min_confidence=50,
    )
    connector.process_message()
    sent = [o for b in helper.bundles for o in b["bundle"]["objects"]]
    assert {o["name"] for o in sent if o["type"] == "malware"} == {"Socks"}
    assert any(
        "skipped by the family or confidence filters" in m
        for m in fake_logger.messages("info")
    )


def test_filtered_samples_do_not_count_against_max_objects(fake_logger):
    kept = make_sample_bundle(3, family="Socks")
    pages = {
        "trustgroup": [
            page(
                make_sample_bundle(1, family="Mole"),
                make_sample_bundle(2, family="Mole"),
                more=True,
                next_token="n1",
                last="T1",
            ),
            page(kept, last="T2"),
        ]
    }
    # One sample is about 20 objects. A page of two filtered samples sends
    # nothing, so the budget is untouched and the second page is fetched.
    connector, helper, client = build(
        fake_logger, pages, feed_families="Socks", max_objects_per_run=5
    )
    connector.process_message()
    assert len(client.calls) == 2
    assert len(helper.bundles) == 1
    assert helper.stored_state["collections"]["trustgroup"]["added_after"] == "T2"


def test_filters_do_not_change_collection_cursor(fake_logger):
    pages = {"trustgroup": [page(make_sample_bundle(1, family="Mole"), last="T1")]}
    connector, helper, _ = build(fake_logger, pages, feed_families="Socks")
    connector.process_message()
    assert helper.bundles == []
    assert helper.stored_state["collections"]["trustgroup"]["added_after"] == "T1"


def test_settings_defaults_mean_no_filtering():
    polyswarm = make_settings().polyswarm
    assert polyswarm.feed_families == []
    assert polyswarm.feed_exclude_families == []
    assert polyswarm.feed_min_confidence is None


@pytest.mark.parametrize(
    "value, expected",
    [
        ("Socks, VBClone", ["Socks", "VBClone"]),
        (" Socks , , socks ,Mole", ["Socks", "Mole"]),
        ("", []),
        (["Mole"], ["Mole"]),
    ],
)
def test_family_lists_are_cleaned(value, expected):
    settings = make_settings(feed_families=value, feed_exclude_families=value)
    assert settings.polyswarm.feed_families == expected
    assert settings.polyswarm.feed_exclude_families == expected


@pytest.mark.parametrize(
    "value, expected", [("75", 75), (0, 0), (100, 100), ("", None), (None, None)]
)
def test_min_confidence_accepts_range_and_empty(value, expected):
    settings = make_settings(feed_min_confidence=value)
    assert settings.polyswarm.feed_min_confidence == expected


@pytest.mark.parametrize("value", [-1, 101, "high"])
def test_min_confidence_rejects_out_of_range(value):
    with pytest.raises(ConfigValidationError) as err:
        make_settings(feed_min_confidence=value)
    assert "polyswarm.feed_min_confidence" in str(err.value.__cause__)
