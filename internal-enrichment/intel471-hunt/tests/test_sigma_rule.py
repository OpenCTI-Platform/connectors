"""Sigma normalisation: the metadata quirks OpenCTI's pySigma parser rejects."""

from __future__ import annotations

import pytest
import yaml
from src.sigma_rule import normalise

BASE = """title: Example rule
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '/curl'
  condition: selection
"""


def _load(rule: str) -> dict:
    return yaml.safe_load(rule)


def test_invalid_status_is_dropped():
    result = normalise(BASE + "status: New\n")

    assert "status" not in _load(result)


def test_valid_status_is_kept():
    result = normalise(BASE + "status: experimental\n")

    assert _load(result)["status"] == "experimental"


def test_non_uuid_id_is_dropped():
    result = normalise(BASE + "id: a1b2c3d4-0024-4e5f-a789-teampcp000024\n")

    assert "id" not in _load(result)


def test_uuid_id_is_kept():
    rule_id = "11111111-2222-3333-4444-555555555555"

    result = normalise(BASE + f"id: {rule_id}\n")

    assert _load(result)["id"] == rule_id


def test_nested_tags_are_flattened_and_markers_dropped():
    result = normalise(
        BASE
        + "tags:\n  - ['optional', 'attack.t1059.001', 'threatName.emotet', 'etc']\n"
    )

    # Markers without a namespace would crash pySigma's tag parser.
    assert _load(result)["tags"] == ["attack.t1059.001", "threatName.emotet"]


def test_tags_key_removed_when_nothing_survives():
    result = normalise(BASE + "tags:\n  - ['optional', 'etc']\n")

    assert "tags" not in _load(result)


def test_invalid_level_is_dropped():
    result = normalise(BASE + "level: New\n")

    assert "level" not in _load(result)


def test_detection_and_logsource_are_untouched():
    original = _load(BASE + "status: New\n")

    result = _load(normalise(BASE + "status: New\n"))

    assert result["detection"] == original["detection"]
    assert result["logsource"] == original["logsource"]
    assert result["title"] == original["title"]


def test_clean_rule_is_returned_unchanged():
    assert normalise(BASE) == BASE.strip()


@pytest.mark.parametrize("value", ["", "   ", "\n"])
def test_blank_input_returns_empty(value):
    assert normalise(value) == ""


def test_unparseable_yaml_returns_empty():
    assert normalise("title: [unclosed\n  bad: :\n") == ""


def test_normalised_rule_satisfies_pysigma():
    collection = pytest.importorskip("sigma.collection", reason="pysigma not installed")
    broken = (
        BASE
        + "status: New\n"
        + "id: a1b2c3d4-0024-4e5f-a789-teampcp000024\n"
        + "tags:\n  - ['optional', 'attack.t1059.001', 'etc']\n"
    )

    with pytest.raises(Exception):
        collection.SigmaCollection.from_yaml(broken)

    collection.SigmaCollection.from_yaml(normalise(broken))


def test_rule_rejected_by_pysigma_is_dropped():
    """A defect we cannot repair must yield no rule at all, rather than one the
    platform will reject along with every relationship pointing at it."""
    pytest.importorskip("sigma.collection", reason="pysigma not installed")

    # `condition` naming a selection that is not defined.
    broken = "title: Broken\ndetection:\n  condition: selection\n"

    assert normalise(broken) == ""
