"""Live hunting: a Malware object only for real family names.

Engine label style names (Trojan.Packed2, PUA.Generic, ...) keep their place in
the note and in a `polyswarm-family:<name>` label, but create no Malware.
"""

import json
from pathlib import Path

import pytest
from connector import hunting
from test_hunting import by_type, make_hit, make_source

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.mark.parametrize(
    "family", ["Copak", "Satan", "Synaptics", "Impacket", "AsyncRat"]
)
def test_real_family_names_create_malware_and_label(family):
    source, _, _ = make_source([make_hit(malware_family=family)])
    objects, _ = source.collect({})
    malware = by_type(objects, "malware")
    assert [m["name"] for m in malware] == [family]
    label = f"polyswarm-family:{family}"
    assert label in by_type(objects, "indicator")[0]["labels"]
    assert label in by_type(objects, "file")[0]["x_opencti_labels"]
    note = by_type(objects, "note")[0]
    assert label in note["labels"]
    assert "no malware object was created" not in note["content"]
    assert len(note["object_refs"]) == 4


@pytest.mark.parametrize(
    "family",
    [
        "Trojan.Packed2",
        "PUA.Generic",
        "Trojan.JS.Agent",
        "Phishing.HTML.Doc",
        "HkcAURkA",
    ],
)
def test_engine_labels_create_no_malware_but_keep_name_and_label(family):
    source, _, _ = make_source([make_hit(malware_family=family)])
    objects, _ = source.collect({})
    assert by_type(objects, "malware") == []
    assert all(
        r["relationship_type"] != "indicates" for r in by_type(objects, "relationship")
    )
    label = "polyswarm-family:" + hunting._UNSAFE_LABEL_CHARS.sub("_", family)
    assert label in by_type(objects, "indicator")[0]["labels"]
    assert label in by_type(objects, "file")[0]["x_opencti_labels"]
    note = by_type(objects, "note")[0]
    assert label in note["labels"]
    assert f"Malware family as reported: {family}" in note["content"]
    assert "no malware object was created" in note["content"]
    # Only the file and the indicator are referenced by the note.
    assert len(note["object_refs"]) == 2


def test_no_family_means_no_family_label():
    source, _, _ = make_source([make_hit(malware_family=None)])
    objects, _ = source.collect({})
    assert by_type(objects, "indicator")[0]["labels"] == ["polyswarm-hunt:example_rule"]
    assert by_type(objects, "note")[0]["labels"] == ["polyswarm-hunt:example_rule"]


def test_recorded_hunting_page_applies_the_family_rule():
    """Trojan.JS.Agent is a label (no Malware), Impacket is a family."""
    page = json.loads((FIXTURES / "hunt_live_last_page.json").read_text())
    source, _, _ = make_source(page["result"])
    objects, _ = source.collect({})
    assert [m["name"] for m in by_type(objects, "malware")] == ["Impacket"]
    labels = {label for o in by_type(objects, "indicator") for label in o["labels"]}
    assert "polyswarm-family:Trojan.JS.Agent" in labels
    assert "polyswarm-family:Impacket" in labels
