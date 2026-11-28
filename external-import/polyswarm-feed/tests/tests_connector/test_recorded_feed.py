"""Run the recorded, scrubbed feed pages through the converter."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from connector.connector import build_author, build_tlp_marking
from connector.converter import FeedConverter

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PAGES = [
    "taxii_objects_trustgroup_page1.json",
    "taxii_objects_trustgroup_page2.json",
    "taxii_objects_ransomware_page1.json",
    "taxii_objects_freemium_page1.json",
]
NOW = datetime(2026, 11, 10, 15, 0, 0, tzinfo=timezone.utc)


def _convert(page, fake_logger):
    items = json.loads((FIXTURES / page).read_text())["objects"]
    converter = FeedConverter(
        author=build_author(),
        tlp_marking=build_tlp_marking("clear"),
        indicator_valid_days=90,
        logger=fake_logger,
        now=NOW,
    )
    return items, converter.convert_page(items)


@pytest.mark.parametrize("page", PAGES)
def test_each_sample_keeps_three_distinct_hash_indicators(page, fake_logger):
    items, objects = _convert(page, fake_logger)
    indicators = [o for o in objects if o["type"] == "indicator"]
    assert len(indicators) == 3 * len(items)
    assert len({o["id"] for o in indicators}) == len(indicators)
    assert all(o["pattern"].startswith("[file:hashes.") for o in indicators)


@pytest.mark.parametrize("page", PAGES)
def test_no_dangling_references(page, fake_logger):
    _, objects = _convert(page, fake_logger)
    ids = {o["id"] for o in objects} | {
        build_author()["id"],
        build_tlp_marking("clear")["id"],
    }
    for obj in objects:
        for key, value in obj.items():
            refs = value if key.endswith("_refs") else [value]
            if key.endswith("_ref") or key.endswith("_refs"):
                for ref in refs:
                    assert ref in ids, (obj["type"], key, ref)


@pytest.mark.parametrize("page", PAGES)
def test_every_indicator_is_valid_after_import(page, fake_logger):
    _, objects = _convert(page, fake_logger)
    for obj in objects:
        if obj["type"] == "indicator":
            assert obj["valid_until"] > NOW.strftime("%Y-%m-%dT%H:%M:%S")
            assert obj["valid_until"] > obj["valid_from"]


def test_freemium_keeps_attack_patterns(fake_logger):
    _, objects = _convert("taxii_objects_freemium_page1.json", fake_logger)
    assert any(o["type"] == "attack-pattern" for o in objects)


@pytest.mark.parametrize("page", PAGES)
def test_analyses_fit_what_opencti_accepts(page, fake_logger):
    items, objects = _convert(page, fake_logger)
    by_id = {o["id"]: o for o in objects}
    relationship_types = {
        o["relationship_type"] for o in objects if o["type"] == "relationship"
    }
    assert not relationship_types & {"av-analysis-of", "dynamic-analysis-of"}
    analyses = [o for o in objects if o["type"] == "malware-analysis"]
    assert analyses
    for analysis in analyses:
        assert analysis["result_name"]
        assert analysis["submitted"]
        assert by_id[analysis["sample_ref"]]["type"] == "file"


@pytest.mark.parametrize("page", PAGES)
def test_no_variant_of_between_same_named_malware(page, fake_logger):
    _, objects = _convert(page, fake_logger)
    by_id = {o["id"]: o for o in objects}
    for obj in objects:
        if obj["type"] == "relationship" and obj["relationship_type"] == "variant-of":
            source = by_id[obj["source_ref"]]["name"].lower()
            assert source != by_id[obj["target_ref"]]["name"].lower()
