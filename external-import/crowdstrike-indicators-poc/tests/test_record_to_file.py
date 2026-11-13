"""Tests for recording STIX bundles to files."""

import json
from typing import Any
from unittest import mock

import pytest
import stix2
from conftest import load_fixture
from crowdstrike_indicators.bundle import MakeStixBundle
from crowdstrike_indicators.malware import CrowdStrikeAddMalware
from crowdstrike_indicators.models import CrowdStrikeIndicator
from crowdstrike_indicators.transformer import CrowdStrikeIndicatorTransformer

from shared.record_to_file import RecordToFile

SAMPLE_ROWS = load_fixture("indicators_sample.json")["resources"]
DOMAIN_7 = next(row for row in SAMPLE_ROWS if row["id"] == "domain_malicious-7.example")
BUNDLE_ID = "bundle--fe24cab3-d021-56f9-af58-867c5a0cdb23"


def stix_bundle(raw: dict[str, Any]) -> stix2.v21.Bundle:
    indicator = CrowdStrikeIndicatorTransformer().convert(
        CrowdStrikeIndicator.model_validate(raw)
    )
    return MakeStixBundle().convert(CrowdStrikeAddMalware().convert(indicator))


BUNDLE = stix_bundle(DOMAIN_7)


def files_in(directory) -> list[str]:
    return sorted(path.name for path in directory.iterdir())


def test_file_is_named_after_the_bundle_id(tmp_path):
    out = tmp_path / "out"

    assert RecordToFile(out).load(BUNDLE) is None

    assert BUNDLE.id == BUNDLE_ID
    assert files_in(out) == [f"{BUNDLE_ID}.json"]


def test_missing_directory_is_created(tmp_path):
    out = tmp_path / "a" / "b" / "c"
    loader = RecordToFile(out)
    assert not out.exists()  # building the loader has no side effect

    loader.load(BUNDLE)

    assert (out / f"{BUNDLE_ID}.json").is_file()


def test_file_reads_back_to_the_same_bundle(tmp_path):
    loader = RecordToFile(tmp_path)
    loader.load(BUNDLE)

    text = loader.path_for(BUNDLE).read_text(encoding="utf-8")
    parsed = stix2.parse(text, allow_custom=True)

    assert text.endswith("}\n")
    assert parsed.id == BUNDLE.id
    assert [o.id for o in parsed.objects] == [o.id for o in BUNDLE.objects]
    assert parsed.objects[0]["x_crowdstrike_marker"] == DOMAIN_7["_marker"]


def test_file_is_indented_utf8_json(tmp_path):
    loader = RecordToFile(tmp_path)
    loader.load(BUNDLE)

    raw = loader.path_for(BUNDLE).read_bytes()

    assert json.loads(raw.decode("utf-8"))["type"] == "bundle"
    assert b'\n    "' in raw


def test_same_bundle_gives_the_same_bytes_and_one_file(tmp_path):
    loader = RecordToFile(tmp_path)
    loader.load(BUNDLE)
    first = loader.path_for(BUNDLE).read_bytes()

    loader.load(stix_bundle(DOMAIN_7))

    assert files_in(tmp_path) == [f"{BUNDLE_ID}.json"]
    assert loader.path_for(BUNDLE).read_bytes() == first


def test_write_failure_leaves_no_file(tmp_path):
    loader = RecordToFile(tmp_path)

    with mock.patch("os.replace", side_effect=OSError("disk full")):
        with pytest.raises(OSError, match="disk full"):
            loader.load(BUNDLE)

    assert files_in(tmp_path) == []


def test_write_failure_keeps_the_previous_file(tmp_path):
    loader = RecordToFile(tmp_path)
    loader.load(BUNDLE)
    previous = loader.path_for(BUNDLE).read_bytes()

    with mock.patch("os.fsync", side_effect=OSError("io error")):
        with pytest.raises(OSError, match="io error"):
            loader.load(BUNDLE)

    assert files_in(tmp_path) == [f"{BUNDLE_ID}.json"]
    assert loader.path_for(BUNDLE).read_bytes() == previous


def test_directory_path_that_is_a_file_raises(tmp_path):
    not_a_directory = tmp_path / "out"
    not_a_directory.write_text("x")

    with pytest.raises(OSError):
        RecordToFile(not_a_directory).load(BUNDLE)
