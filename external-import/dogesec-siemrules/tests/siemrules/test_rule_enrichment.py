"""Tests for the rule metadata and ATT&CK links added to SIEM Rules bundles."""

from unittest.mock import MagicMock

import pytest
from pycti import AttackPattern, StixCoreRelationship
from rule_enrichment import (
    RuleEnricher,
    mitre_technique_names,
    parse_sigma_rule,
    rule_metadata,
    technique_ids,
)

IDENTITY_ID = "identity--a4d70b75-6f4a-5d19-9137-da863edd33d7"
MARKING_ID = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
MITRE_T1059 = "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830"

SIGMA_RULE = """\
title: Encoded PowerShell
id: 5b3d4a2c-0000-4000-8000-000000000001
status: experimental
level: High
logsource:
  product: Windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: ' -enc '
  condition: selection
tags:
  - attack.execution
  - attack.t1059
  - attack.T1059.001
  - attack.t1059
  - cve.2024-1234
"""


def _indicator(pattern: str = SIGMA_RULE, **extra) -> dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5b3d4a2c-0000-4000-8000-000000000001",
        "created_by_ref": IDENTITY_ID,
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": "Encoded PowerShell",
        "pattern_type": "sigma",
        "pattern": pattern,
        "valid_from": "2026-01-01T00:00:00.000Z",
        "object_marking_refs": [MARKING_ID],
        **extra,
    }


def _mitre_attack_pattern() -> dict:
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": MITRE_T1059,
        "name": "Command and Scripting Interpreter",
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1059"}
        ],
    }


def _enricher(known: list[str] | Exception) -> RuleEnricher:
    helper = MagicMock()
    if isinstance(known, Exception):
        helper.api.attack_pattern.list.side_effect = known
    else:
        helper.api.attack_pattern.list.return_value = [
            {
                "standard_id": AttackPattern.generate_id(mitre_id, mitre_id),
                "x_opencti_stix_ids": [],
            }
            for mitre_id in known
        ]
    return RuleEnricher(helper)


def test_technique_ids_are_deduplicated_and_tactics_ignored():
    assert technique_ids(parse_sigma_rule(SIGMA_RULE)) == ["T1059", "T1059.001"]


def test_rule_metadata_from_the_sigma_document():
    assert rule_metadata(parse_sigma_rule(SIGMA_RULE), {}) == {
        "x_opencti_rule_status": "experimental",
        "x_opencti_rule_level": "high",
        "x_opencti_rule_logsource": {
            "product": "windows",
            "category": "process_creation",
        },
    }


def test_rule_metadata_falls_back_to_siemrules_properties():
    document = {"title": "x", "status": "not-a-status"}
    assert rule_metadata(
        document, {"x_sigma_status": "Test", "x_sigma_level": "critical"}
    ) == {"x_opencti_rule_status": "test", "x_opencti_rule_level": "critical"}


@pytest.mark.parametrize("pattern", ["", "- just\n- a list", "key: [unclosed"])
def test_unparsable_patterns(pattern):
    assert parse_sigma_rule(pattern) is None


def test_mitre_names_read_from_the_bundle():
    assert mitre_technique_names(
        [_mitre_attack_pattern(), {"type": "attack-pattern", "name": "No refs"}]
    ) == {"T1059": "Command and Scripting Interpreter"}


def test_enrich_adds_metadata_and_indicates_links():
    enricher = _enricher(known=["T1059.001"])
    indicator = _indicator()
    objects = enricher.enrich([indicator, _mitre_attack_pattern()])

    assert indicator["x_opencti_rule_level"] == "high"
    relationships = [o for o in objects if o["type"] == "relationship"]
    t1059 = AttackPattern.generate_id("T1059", "T1059")
    t1059_001 = AttackPattern.generate_id("T1059.001", "T1059.001")
    assert sorted(r["target_ref"] for r in relationships) == sorted([t1059, t1059_001])
    for relationship in relationships:
        assert relationship["relationship_type"] == "indicates"
        assert relationship["source_ref"] == indicator["id"]
        assert relationship["id"] == StixCoreRelationship.generate_id(
            "indicates", indicator["id"], relationship["target_ref"]
        )
        assert relationship["created_by_ref"] == IDENTITY_ID
        assert relationship["object_marking_refs"] == [MARKING_ID]
    # T1059.001 is held by the platform: referenced only. T1059 is not:
    # created under the MITRE ATT&CK name the bundle carries.
    patterns = [
        o for o in objects if o["type"] == "attack-pattern" and o["id"] != MITRE_T1059
    ]
    assert len(patterns) == 1
    assert patterns[0]["id"] == t1059
    assert patterns[0]["name"] == "Command and Scripting Interpreter"
    assert patterns[0]["x_mitre_id"] == "T1059"


def test_lookups_are_cached_for_the_run_and_reset():
    enricher = _enricher(known=[])
    enricher.enrich([_indicator()])
    enricher.enrich([_indicator()])
    assert enricher.helper.api.attack_pattern.list.call_count == 1
    enricher.reset()
    enricher.enrich([_indicator()])
    assert enricher.helper.api.attack_pattern.list.call_count == 2


def test_lookup_failure_never_renames_a_technique():
    enricher = _enricher(known=RuntimeError("platform down"))
    objects = enricher.enrich([_indicator(), _mitre_attack_pattern()])

    created = {
        o["x_mitre_id"]: o["name"]
        for o in objects
        if o["type"] == "attack-pattern" and "x_mitre_id" in o
    }
    # The bundle carries T1059's real name: safe to create. T1059.001 has no
    # known name: referenced only.
    assert created == {"T1059": "Command and Scripting Interpreter"}
    assert len([o for o in objects if o["type"] == "relationship"]) == 2
    enricher.helper.connector_logger.warning.assert_called_once()


def test_non_sigma_objects_are_untouched():
    enricher = _enricher(known=[])
    yara = _indicator(pattern="rule x { condition: true }", pattern_type="yara")
    broken = _indicator(pattern="key: [unclosed")
    objects = enricher.enrich([yara, broken])
    assert objects == [yara, broken]
    assert "x_opencti_rule_level" not in yara
    enricher.helper.api.attack_pattern.list.assert_not_called()
