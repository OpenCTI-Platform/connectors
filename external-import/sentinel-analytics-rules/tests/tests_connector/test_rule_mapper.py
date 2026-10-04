import json
from datetime import datetime, timezone

import pytest
from connector.detection_rule import RuleSkippedError
from connector.rule_mapper import map_rule
from sentinel_samples import FUSION_RULE, NRT_RULE, SCHEDULED_RULE, rule


def test_scheduled_rule():
    detection_rule = map_rule(SCHEDULED_RULE)
    assert detection_rule.external_id == "73e01a99-5cd7-4139-a149-9f2736ff2ab5"
    assert detection_rule.name == "Encoded PowerShell"
    assert detection_rule.description == "Detects encoded PowerShell command lines."
    assert detection_rule.pattern == SCHEDULED_RULE["properties"]["query"]
    assert detection_rule.pattern_type == "kql"
    assert detection_rule.enabled is True
    assert detection_rule.level == "high"
    # Seven fractional digits are truncated to microseconds.
    assert detection_rule.created_at == datetime(
        2026, 1, 2, 3, 4, 5, 123456, tzinfo=timezone.utc
    )
    assert detection_rule.modified_at == datetime(2026, 9, 1, 10, tzinfo=timezone.utc)
    assert detection_rule.techniques == {"T1059": None, "T1059.001": None}
    assert detection_rule.platforms == []
    assert detection_rule.logsource is None
    assert detection_rule.url is None


def test_trigger_threshold_is_part_of_the_pattern():
    raw = rule(SCHEDULED_RULE, triggerThreshold=100)
    detection_rule = map_rule(raw)
    assert detection_rule.pattern_type == "sentinel-rule"
    assert json.loads(detection_rule.pattern) == {
        "kind": "Scheduled",
        "query": SCHEDULED_RULE["properties"]["query"],
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 100,
    }


def test_trigger_change_changes_the_pattern():
    patterns = {
        map_rule(rule(SCHEDULED_RULE, triggerThreshold=threshold)).pattern
        for threshold in (0, 5, 100)
    } | {map_rule(rule(SCHEDULED_RULE, triggerOperator="LessThan")).pattern}
    assert len(patterns) == 4


def test_default_trigger_keeps_the_query_as_pattern():
    for raw in (
        rule(SCHEDULED_RULE, triggerOperator=None, triggerThreshold=None),
        rule(SCHEDULED_RULE, triggerThreshold="0"),
    ):
        detection_rule = map_rule(raw)
        assert (detection_rule.pattern_type, detection_rule.pattern) == (
            "kql",
            SCHEDULED_RULE["properties"]["query"],
        )


def test_nrt_rule():
    detection_rule = map_rule(NRT_RULE)
    assert detection_rule.pattern_type == "kql"
    assert detection_rule.enabled is False
    assert detection_rule.level == "informational"
    assert detection_rule.created_at is None
    assert detection_rule.modified_at is None
    # Tactic ids are not techniques.
    assert detection_rule.techniques == {"T1530": None}


def test_modified_time_falls_back_to_system_data():
    raw = rule(SCHEDULED_RULE, lastModifiedUtc=None)
    assert map_rule(raw).modified_at == datetime(2026, 8, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "raw,reason",
    [
        (FUSION_RULE, "kind_Fusion"),
        ({"name": "x", "properties": {}}, "kind_unknown"),
        (rule(SCHEDULED_RULE, query="  "), "no_query"),
        ({**SCHEDULED_RULE, "name": None}, "no_rule_id"),
    ],
)
def test_rules_left_out(raw, reason):
    with pytest.raises(RuleSkippedError) as error:
        map_rule(raw)
    assert error.value.reason == reason
