"""Tests for the Valhalla rule -> STIX mapping (rule metadata and ATT&CK)."""

import json
from unittest.mock import MagicMock

import pytest
from pycti import AttackPattern, StixCoreRelationship
from stix2 import TLP_WHITE
from valhalla.attack_patterns import technique_id
from valhalla.knowledge import KnowledgeImporter
from valhalla.models import YaraRule

MITRE_GROUP_ID = "intrusion-set--bef4c620-0787-42a8-a96d-b7eb6e85917c"
MITRE_DATA = {
    "type": "bundle",
    "id": "bundle--00000000-0000-4000-8000-000000000000",
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830",
            "name": "Command and Scripting Interpreter",
            "external_references": [{"external_id": "T1059"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736",
            "name": "PowerShell",
            "external_references": [{"external_id": "T1059.001"}],
        },
        {
            "type": "intrusion-set",
            "id": MITRE_GROUP_ID,
            "name": "APT29",
            "external_references": [{"external_id": "G0016"}],
        },
    ],
}


def _rule(name: str, tags: list[str], score: int = 75) -> dict:
    return {
        "author": "Florian Roth",
        "content": f'rule {name} {{ strings: $a = "{name}" condition: $a }}',
        "date": "2026-01-02 03:04:05",
        "description": f"Detects {name}",
        "minimum_yara": "3.0",
        "name": name,
        "reference": "-",
        "required_modules": [],
        "rule_hash": name,
        "score": score,
        "tags": tags,
    }


def _rules_response(rules: list[dict]) -> dict:
    return {
        "api_version": "1",
        "copyright": "Nextron Systems",
        "customer": "test",
        "date": "2026-01-02 03:04:05",
        "legal_note": "-",
        "title": "Valhalla",
        "rules": rules,
    }


def _importer(rules: list[dict], known_techniques: list[str]) -> KnowledgeImporter:
    helper = MagicMock()
    helper.api.attack_pattern.list.return_value = [
        {
            "standard_id": AttackPattern.generate_id(mitre_id, mitre_id),
            "x_opencti_stix_ids": [],
        }
        for mitre_id in known_techniques
    ]
    client = MagicMock()
    client.get_rules_json.return_value = _rules_response(rules)
    return KnowledgeImporter(helper, TLP_WHITE, client)


@pytest.fixture(autouse=True)
def mitre_download(monkeypatch):
    response = MagicMock()
    response.json.return_value = MITRE_DATA
    get = MagicMock(return_value=response)
    monkeypatch.setattr("valhalla.knowledge.requests.get", get)
    return get


def _run(importer: KnowledgeImporter) -> list:
    importer.run(work_id="work-1")
    bundle = json.loads(importer.helper.send_stix2_bundle.call_args[0][0])
    return bundle["objects"]


@pytest.mark.parametrize(
    "tag,expected",
    [
        ("T1059", "T1059"),
        ("t1059.001", "T1059.001"),
        (" T1003 ", "T1003"),
        ("T105", None),
        ("T1059.1", None),
        ("G0016", None),
        ("APT", None),
        ("", None),
    ],
)
def test_technique_id(tag, expected):
    assert technique_id(tag) == expected


@pytest.mark.parametrize(
    "score,level",
    [
        (0, "informational"),
        (39, "informational"),
        (40, "low"),
        (59, "low"),
        (60, "medium"),
        (79, "medium"),
        (80, "high"),
        (100, "high"),
    ],
)
def test_rule_level_follows_the_nextron_score_ranges(score, level):
    assert YaraRule.parse_obj(_rule("R", [], score)).rule_level == level


def test_sub_techniques_link_to_their_deterministic_attack_pattern():
    importer = _importer([_rule("RuleA", ["T1059.001", "MAL"])], known_techniques=[])
    objects = _run(importer)

    indicator = next(o for o in objects if o["type"] == "indicator")
    assert indicator["x_opencti_rule_level"] == "medium"
    target_id = AttackPattern.generate_id("T1059.001", "T1059.001")
    relationship = next(o for o in objects if o["type"] == "relationship")
    assert relationship["relationship_type"] == "indicates"
    assert relationship["target_ref"] == target_id
    assert relationship["id"] == StixCoreRelationship.generate_id(
        "indicates", indicator["id"], target_id
    )
    # Not held by the platform yet: created under its MITRE ATT&CK name.
    pattern = next(o for o in objects if o["type"] == "attack-pattern")
    assert pattern["id"] == target_id
    assert pattern["name"] == "PowerShell"
    assert pattern["x_mitre_id"] == "T1059.001"
    assert pattern["created_by_ref"] == importer.organization.id


def test_techniques_held_by_the_platform_are_referenced_only():
    importer = _importer([_rule("RuleA", ["T1059"])], known_techniques=["T1059"])
    objects = _run(importer)

    assert [o for o in objects if o["type"] == "attack-pattern"] == []
    relationship = next(o for o in objects if o["type"] == "relationship")
    assert relationship["target_ref"] == AttackPattern.generate_id("T1059", "T1059")


def test_unknown_tags_do_not_stop_the_import():
    importer = _importer(
        [
            _rule("RuleA", ["G9999", "T1059"]),
            _rule("RuleB", ["G0016", "T1059"]),
        ],
        known_techniques=[],
    )
    objects = _run(importer)

    indicators = [o for o in objects if o["type"] == "indicator"]
    assert {i["name"] for i in indicators} == {"RuleA", "RuleB"}
    relationships = [o for o in objects if o["type"] == "relationship"]
    targets = sorted(r["target_ref"] for r in relationships)
    technique = AttackPattern.generate_id("T1059", "T1059")
    assert targets == sorted([technique, technique, MITRE_GROUP_ID])
    # The shared technique is created once for the whole bundle.
    assert len([o for o in objects if o["type"] == "attack-pattern"]) == 1


def test_platform_is_asked_once_for_every_technique():
    importer = _importer(
        [_rule("RuleA", ["T1059"]), _rule("RuleB", ["t1059.001", "T1059"])],
        known_techniques=[],
    )
    _run(importer)

    calls = importer.helper.api.attack_pattern.list.call_args_list
    assert len(calls) == 1
    assert sorted(calls[0].kwargs["filters"]["filters"][0]["values"]) == sorted(
        [
            AttackPattern.generate_id("T1059", "T1059"),
            AttackPattern.generate_id("T1059.001", "T1059.001"),
        ]
    )


def test_technique_created_under_its_id_when_attack_data_is_unavailable(
    mitre_download,
):
    mitre_download.side_effect = RuntimeError("github down")
    importer = _importer([_rule("RuleA", ["T1059"])], known_techniques=[])
    objects = _run(importer)

    pattern = next(o for o in objects if o["type"] == "attack-pattern")
    assert pattern["name"] == "T1059"
