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


def test_cti_pattern_does_not_repeat_imports():
    """A module listed twice or already imported in the content is imported once."""
    rule_data = make_rule("PE_Rule", "pe.is_32bit()", required_modules=["pe", "pe"])
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
