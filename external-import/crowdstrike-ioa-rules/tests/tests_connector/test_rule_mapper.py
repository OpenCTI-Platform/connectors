import json
from datetime import datetime, timezone

import pytest
from connector.detection_rule import RuleSkippedError
from connector.rule_mapper import (
    ioa_rule_id,
    iter_rules,
    map_rule,
    rule_pattern,
)
from crowdstrike_samples import DNS_RULE, MAC_GROUP, PROCESS_RULE, WINDOWS_GROUP, group


def test_process_creation_rule():
    rule = map_rule(WINDOWS_GROUP, PROCESS_RULE)
    assert rule.external_id == "0a1b2c3d4e5f60718293a4b5c6d7e8f9/1"
    assert rule.name == "Encoded PowerShell (T1059.001)"
    assert rule.pattern_type == "crowdstrike-ioa"
    assert rule.enabled is True
    assert rule.level == "high"
    assert rule.platforms == ["windows"]
    assert rule.logsource == {"category": "process_creation", "product": "windows"}
    assert rule.created_at == datetime(2026, 1, 2, 3, 4, 5, 892315, tzinfo=timezone.utc)
    assert rule.modified_at == datetime(2026, 9, 1, 10, tzinfo=timezone.utc)
    # Ids written in the name and the description.
    assert rule.techniques == {"T1059.001": None, "T1027": None}


def test_pattern_is_the_canonical_rule_logic():
    pattern = json.loads(rule_pattern(PROCESS_RULE))
    assert pattern["ruletype_name"] == "Process Creation"
    assert pattern["action_label"] == "Kill Process"
    assert pattern["disposition_id"] == 30
    assert [f["name"] for f in pattern["field_values"]] == [
        "CommandLine",
        "ImageFilename",
    ]
    # Field order, names and comments do not change the logic, hence the pattern.
    shuffled = dict(PROCESS_RULE, name="renamed", comment="x")
    shuffled["field_values"] = list(reversed(PROCESS_RULE["field_values"]))
    assert rule_pattern(shuffled) == rule_pattern(PROCESS_RULE)
    assert rule_pattern(dict(PROCESS_RULE, action_label="Block")) != rule_pattern(
        PROCESS_RULE
    )


def test_disabled_rule_or_group():
    assert map_rule(WINDOWS_GROUP, DNS_RULE).enabled is False
    mac_rule = map_rule(MAC_GROUP, MAC_GROUP["rules"][0])
    # The rule is enabled but its group is not.
    assert mac_rule.enabled is False
    assert mac_rule.platforms == ["macos"]


def test_rule_of_a_group_outside_prevention_policies_is_not_enabled():
    assert map_rule(WINDOWS_GROUP, PROCESS_RULE, enforced=False).enabled is False
    assert map_rule(WINDOWS_GROUP, PROCESS_RULE, enforced=True).enabled is True


def test_minimal_rule():
    rule = map_rule(WINDOWS_GROUP, DNS_RULE)
    assert rule.level == "informational"
    assert rule.description is None
    assert rule.techniques == {}
    assert rule.created_at is None
    assert rule.logsource == {"category": "dns_query", "product": "windows"}


def test_group_techniques_apply_to_rules_without_any():
    technique_group = group(
        WINDOWS_GROUP,
        name="Exfiltration (T1041)",
        description="See https://attack.mitre.org/techniques/T1567/002/",
    )
    assert map_rule(technique_group, DNS_RULE).techniques == {
        "T1041": None,
        "T1567.002": None,
    }
    # Techniques of the rule itself win over those of its group.
    assert map_rule(technique_group, PROCESS_RULE).techniques == {
        "T1059.001": None,
        "T1027": None,
    }


@pytest.mark.parametrize(
    "ruletype_name,category",
    [
        ("Process Creation", "process_creation"),
        ("File Creation", "file_event"),
        ("Network Connection", "network_connection"),
        ("Domain Name", "dns_query"),
        ("Process Creation (mac)", None),
        (None, None),
    ],
)
def test_rule_type_log_source_category(ruletype_name, category):
    rule = map_rule(
        group(WINDOWS_GROUP, platform="ios"),
        dict(PROCESS_RULE, ruletype_name=ruletype_name),
    )
    assert rule.logsource == ({"category": category} if category else None)


def test_unknown_platform():
    rule = map_rule(group(WINDOWS_GROUP, platform="ios"), PROCESS_RULE)
    assert rule.platforms == []
    assert rule.logsource == {"category": "process_creation"}


@pytest.mark.parametrize(
    "rule_group,rule,reason",
    [
        (group(WINDOWS_GROUP, deleted=True), PROCESS_RULE, "deleted"),
        (WINDOWS_GROUP, dict(PROCESS_RULE, deleted=True), "deleted"),
        (WINDOWS_GROUP, dict(PROCESS_RULE, instance_id=None), "no_rule_id"),
        (group(WINDOWS_GROUP, id=None), PROCESS_RULE, "no_rule_id"),
    ],
)
def test_rules_left_out(rule_group, rule, reason):
    with pytest.raises(RuleSkippedError) as error:
        map_rule(rule_group, rule)
    assert error.value.reason == reason


def test_iter_rules_flattens_groups():
    triples = iter_rules([WINDOWS_GROUP, MAC_GROUP, {"id": "empty", "rules": None}])
    assert [(g["id"], r["instance_id"], e) for g, r, e in triples] == [
        (WINDOWS_GROUP["id"], "1", True),
        (WINDOWS_GROUP["id"], "2", True),
        (MAC_GROUP["id"], "7", True),
    ]


def test_iter_rules_flags_groups_outside_prevention_policies():
    triples = iter_rules([WINDOWS_GROUP, MAC_GROUP], {MAC_GROUP["id"]})
    assert [(r["instance_id"], e) for _, r, e in triples] == [
        ("1", False),
        ("2", False),
        ("7", True),
    ]


def test_ioa_rule_id():
    assert ioa_rule_id("group", "12") == "group/12"


def test_same_instance_id_in_two_groups_gets_two_ids():
    ids = {
        map_rule(rule_group, PROCESS_RULE).external_id
        for rule_group in (WINDOWS_GROUP, group(WINDOWS_GROUP, id="0f1e2d3c"))
    }
    assert ids == {f"{WINDOWS_GROUP['id']}/1", "0f1e2d3c/1"}
