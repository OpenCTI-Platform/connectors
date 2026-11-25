"""Tests for `KnowledgeImporter`: YARA patterns that carry their module imports, and
bundles that do not carry the objects of previous runs."""

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from stix2 import TLP_WHITE
from valhalla.knowledge import KnowledgeImporter
from valhalla.models import YaraRule

ENTERPRISE_ATTACK: dict[str, Any] = {
    "type": "bundle",
    "id": "bundle--d3b5b8b5-5b8b-4d3c-9b1e-0b5e8c5f1a01",
    "objects": [],
}


def make_rule(
    name: str,
    condition: str = "true",
    required_modules: list[str] | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Build a rule as returned by the Valhalla API."""
    return {
        "author": "Florian Roth",
        "content": f"rule {name} {{\n   condition:\n      {condition}\n}}",
        "date": "2024-02-23 10:54:31",
        "description": f"Detects {name}",
        "minimum_yara": "3.5.0",
        "name": name,
        "reference": "-",
        "required_modules": required_modules or [],
        "rule_hash": f"hash-{name}",
        "score": 75,
        "tags": tags or [],
    }


def make_rules_response(*rules: dict[str, Any]) -> dict[str, Any]:
    """Build a Valhalla API response holding the given rules."""
    return {
        "api_version": "v1",
        "copyright": "Nextron Systems GmbH",
        "customer": "demo",
        "date": "2026-10-22 09:00:00",
        "legal_note": "-",
        "title": "Valhalla YARA rules",
        "rules": list(rules),
    }


@pytest.fixture
def importer(monkeypatch: pytest.MonkeyPatch) -> KnowledgeImporter:
    """Importer with a mocked helper and Valhalla client, and no ATT&CK download."""
    attack_response = MagicMock()
    attack_response.json.return_value = ENTERPRISE_ATTACK
    monkeypatch.setattr(
        "valhalla.knowledge.requests.get", MagicMock(return_value=attack_response)
    )
    return KnowledgeImporter(MagicMock(), TLP_WHITE, MagicMock())


def run_importer(
    importer: KnowledgeImporter, *rules: dict[str, Any]
) -> list[dict[str, Any]]:
    """Run the importer on the given rules and return the objects of the bundle sent."""
    importer.valhalla_client.get_rules_json.return_value = make_rules_response(*rules)
    importer.helper.send_stix2_bundle.reset_mock()
    importer.run(work_id="work-id")
    bundle = importer.helper.send_stix2_bundle.call_args.args[0]
    return json.loads(bundle)["objects"]


def by_type(objects: list[dict[str, Any]], stix_type: str) -> list[dict[str, Any]]:
    """Keep the objects of the given STIX type."""
    return [obj for obj in objects if obj["type"] == stix_type]


def test_cti_pattern_prepends_required_module_imports():
    """The pattern starts with one `import` per required module, in the API order."""
    rule = YaraRule.parse_obj(
        make_rule("PE_Rule", "pe.is_32bit()", required_modules=["pe", "math"])
    )

    assert rule.cti_pattern == f'import "pe"\nimport "math"\n\n{rule.content}'


def test_cti_pattern_keeps_rules_without_modules_unchanged():
    """The pattern, hence the indicator ID, of a rule without modules stays the same."""
    rule = YaraRule.parse_obj(make_rule("Plain_Rule"))

    assert rule.cti_pattern == rule.content


def test_cti_pattern_imports_a_module_listed_twice_once():
    """A module listed twice in `required_modules` is imported once."""
    rule = YaraRule.parse_obj(
        make_rule("PE_Rule", "pe.is_32bit()", required_modules=["pe", "pe"])
    )

    assert rule.cti_pattern == f'import "pe"\n\n{rule.content}'


@pytest.mark.parametrize(
    "comment",
    [
        pytest.param('// Requires import "pe" in the ruleset header\n', id="line"),
        pytest.param('/*\nimport "pe"\n*/\n', id="block"),
    ],
)
def test_cti_pattern_ignores_imports_in_comments(comment: str):
    """An import mentioned in a comment is not a directive, so it is still added."""
    rule_data = make_rule("PE_Rule", "pe.is_32bit()", required_modules=["pe"])
    rule_data["content"] = comment + rule_data["content"]
    rule = YaraRule.parse_obj(rule_data)

    assert rule.cti_pattern == f'import "pe"\n\n{rule.content}'


def test_cti_pattern_keeps_rules_that_already_import_the_module():
    """A rule importing the module itself keeps its pattern, hence its indicator ID."""
    rule_data = make_rule("PE_Rule", "pe.is_32bit()", required_modules=["pe"])
    rule_data["content"] = 'import "pe"\n\n' + rule_data["content"]
    rule = YaraRule.parse_obj(rule_data)

    assert rule.cti_pattern == rule.content


def test_indicator_pattern_includes_required_module_imports(
    importer: KnowledgeImporter,
):
    """The indicator sent carries the imports, so that the platform accepts it."""
    objects = run_importer(
        importer, make_rule("PE_Rule", "pe.is_32bit()", required_modules=["pe"])
    )

    (indicator,) = by_type(objects, "indicator")
    assert indicator["pattern"].startswith('import "pe"\n\nrule PE_Rule')


def test_run_does_not_send_objects_of_previous_runs_again(
    importer: KnowledgeImporter,
):
    """After a rule is edited upstream, its outdated version is not sent again."""
    run_importer(importer, make_rule("Edited_Rule", "true"))
    objects = run_importer(importer, make_rule("Edited_Rule", "false"))

    (indicator,) = by_type(objects, "indicator")
    assert "false" in indicator["pattern"]
    assert len(by_type(objects, "identity")) == 1


APT34 = "intrusion-set--68ba94ab-78b8-43e7-83e2-aed3466882c6"
OILRIG = "intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d"
APT29 = "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542"
UNC2452 = "intrusion-set--8b3b6a1b-3d0f-4b2a-9c5e-7c1b2d3e4f50"
OLD_GROUP = "intrusion-set--0c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f"
DEAD_END_GROUP = "intrusion-set--2a3b4c5d-6e7f-4a8b-9c0d-1e2f3a4b5c6d"
DEAD_END = "intrusion-set--3b4c5d6e-7f8a-4b9c-8d1e-2f3a4b5c6d7e"
NETWORK_SCAN = "attack-pattern--e3a12395-188d-4051-9a16-ea8e14d07b88"


def attack_object(
    stix_type: str, stix_id: str, external_id: str, revoked: bool = False
) -> dict[str, Any]:
    """Build an ATT&CK object as found in `enterprise-attack.json`."""
    return {
        "type": stix_type,
        "id": stix_id,
        "revoked": revoked,
        "external_references": [
            {"source_name": "mitre-attack", "external_id": external_id}
        ],
    }


def revoked_by(source_ref: str, target_ref: str) -> dict[str, Any]:
    """Build a `revoked-by` relationship as found in `enterprise-attack.json`."""
    return {
        "type": "relationship",
        "id": f"relationship--{source_ref[-12:]}-revoked",
        "relationship_type": "revoked-by",
        "source_ref": source_ref,
        "target_ref": target_ref,
    }


@pytest.fixture
def attack_importer(monkeypatch: pytest.MonkeyPatch) -> KnowledgeImporter:
    """Importer whose ATT&CK download holds revoked groups and their replacements.

    G0057 APT34 is revoked by G0049 OilRig; G0118 UNC2452 is revoked by an object
    itself revoked by G0016 APT29 (a chain); G0001 is revoked with no replacement;
    G0002 is revoked by G0003, itself revoked with no replacement.
    """
    middle = "intrusion-set--11111111-2222-4333-8444-555555555555"
    attack_data = {
        "type": "bundle",
        "id": "bundle--d3b5b8b5-5b8b-4d3c-9b1e-0b5e8c5f1a02",
        "objects": [
            attack_object("intrusion-set", APT34, "G0057", revoked=True),
            attack_object("intrusion-set", OILRIG, "G0049"),
            attack_object("intrusion-set", UNC2452, "G0118", revoked=True),
            attack_object("intrusion-set", middle, "G9999", revoked=True),
            attack_object("intrusion-set", APT29, "G0016"),
            attack_object("intrusion-set", OLD_GROUP, "G0001", revoked=True),
            attack_object("intrusion-set", DEAD_END_GROUP, "G0002", revoked=True),
            attack_object("intrusion-set", DEAD_END, "G0003", revoked=True),
            attack_object("attack-pattern", NETWORK_SCAN, "T1046"),
            revoked_by(APT34, OILRIG),
            revoked_by(UNC2452, middle),
            revoked_by(middle, APT29),
            revoked_by(DEAD_END_GROUP, DEAD_END),
        ],
    }
    attack_response = MagicMock()
    attack_response.json.return_value = attack_data
    monkeypatch.setattr(
        "valhalla.knowledge.requests.get", MagicMock(return_value=attack_response)
    )
    monkeypatch.setattr(KnowledgeImporter, "_ATTACK_MAPPING", {})
    return KnowledgeImporter(MagicMock(), TLP_WHITE, MagicMock())


def indicates_targets(objects: list[dict[str, Any]]) -> set[str]:
    """The target of every `indicates` relationship of the bundle."""
    return {
        rel["target_ref"]
        for rel in by_type(objects, "relationship")
        if rel["relationship_type"] == "indicates"
    }


def test_revoked_group_tag_indicates_the_replacing_group(
    attack_importer: KnowledgeImporter,
):
    """A rule tagged with a revoked group is linked to the group that replaced it."""
    objects = run_importer(attack_importer, make_rule("APT34_Rule", tags=["G0057"]))

    assert indicates_targets(objects) == {OILRIG}


def test_revoked_group_tag_follows_the_revoked_by_chain(
    attack_importer: KnowledgeImporter,
):
    """A chain of `revoked-by` relationships is followed to its end."""
    objects = run_importer(attack_importer, make_rule("UNC2452_Rule", tags=["G0118"]))

    assert indicates_targets(objects) == {APT29}


def test_revoked_group_without_replacement_creates_no_relationship(
    attack_importer: KnowledgeImporter,
):
    """A group revoked with no replacement gets no relationship, the rule stays."""
    objects = run_importer(attack_importer, make_rule("Old_Rule", tags=["G0001"]))

    assert len(by_type(objects, "indicator")) == 1
    assert indicates_targets(objects) == set()


def test_revoked_chain_ending_at_a_revoked_object_creates_no_relationship(
    attack_importer: KnowledgeImporter,
):
    """A chain whose last object is itself revoked gets no relationship."""
    objects = run_importer(
        attack_importer, make_rule("Dead_End_Rule", tags=["G0002", "G0003"])
    )

    assert len(by_type(objects, "indicator")) == 1
    assert indicates_targets(objects) == set()


def test_unknown_tag_does_not_drop_the_remaining_rules(
    attack_importer: KnowledgeImporter,
):
    """A tag without an ATT&CK match skips that tag only, not the rest of the feed."""
    objects = run_importer(
        attack_importer,
        make_rule("Unknown_Tags_Rule", tags=["G0404", "T0404", "T1046"]),
        make_rule("APT34_Rule", tags=["G0057"]),
    )

    assert len(by_type(objects, "indicator")) == 2
    assert indicates_targets(objects) == {NETWORK_SCAN, OILRIG}
