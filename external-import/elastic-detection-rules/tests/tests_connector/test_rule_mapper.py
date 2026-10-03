from datetime import datetime, timezone

import pytest
from connector.detection_rule import RuleSkippedError
from connector.rule_mapper import map_rule
from elastic_samples import (
    EQL_RULE,
    ESQL_RULE,
    KUERY_RULE,
    LUCENE_RULE,
    ML_RULE,
    rule,
)


def _url(saved_object_id: str) -> str:
    return f"https://kibana.example.com/app/security/rules/id/{saved_object_id}"


def test_kuery_rule():
    detection_rule = map_rule(KUERY_RULE, _url)
    assert detection_rule.external_id == KUERY_RULE["rule_id"]
    assert detection_rule.name == "Encoded PowerShell Command"
    assert detection_rule.pattern == KUERY_RULE["query"]
    assert detection_rule.pattern_type == "kuery"
    assert detection_rule.enabled is True
    assert detection_rule.level == "high"
    assert detection_rule.created_at == datetime(
        2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc
    )
    assert detection_rule.modified_at == datetime(2026, 9, 1, 10, tzinfo=timezone.utc)
    assert detection_rule.techniques == {
        "T1059": "Command and Scripting Interpreter",
        "T1059.001": "PowerShell",
    }
    assert detection_rule.platforms == ["windows"]
    assert detection_rule.logsource == {"product": "windows"}
    assert detection_rule.url == _url(KUERY_RULE["id"])


def test_eql_rule_without_language_field():
    detection_rule = map_rule(EQL_RULE, _url)
    assert detection_rule.pattern_type == "eql"
    assert detection_rule.enabled is False
    assert detection_rule.level == "critical"
    assert detection_rule.description is None
    # Only the MITRE ATT&CK framework counts.
    assert detection_rule.techniques == {"T1003": "OS Credential Dumping"}
    # Several operating systems: no single log source product.
    assert detection_rule.platforms == ["windows", "linux"]
    assert detection_rule.logsource is None


@pytest.mark.parametrize(
    "raw,pattern_type", [(ESQL_RULE, "esql"), (LUCENE_RULE, "lucene")]
)
def test_other_languages(raw, pattern_type):
    detection_rule = map_rule(raw, _url)
    assert detection_rule.pattern_type == pattern_type
    assert detection_rule.techniques == {}
    assert detection_rule.platforms == []


def test_missing_dates_and_severity():
    detection_rule = map_rule(LUCENE_RULE, _url)
    assert detection_rule.created_at is None
    assert detection_rule.modified_at is None
    assert detection_rule.level == "medium"
    assert map_rule(rule(LUCENE_RULE, severity="unknown"), _url).level is None


def test_no_url_without_saved_object_id():
    assert map_rule(rule(LUCENE_RULE, id=None), _url).url is None


@pytest.mark.parametrize(
    "raw,reason",
    [
        (ML_RULE, "machine_learning"),
        (rule(KUERY_RULE, query=""), "no_query"),
        (rule(KUERY_RULE, query=None), "no_query"),
        (rule(KUERY_RULE, language="sql"), "language_sql"),
        (rule(KUERY_RULE, rule_id=None), "no_rule_id"),
    ],
)
def test_rules_left_out(raw, reason):
    with pytest.raises(RuleSkippedError) as error:
        map_rule(raw, _url)
    assert error.value.reason == reason


def test_invalid_technique_ids_are_ignored():
    raw = rule(
        KUERY_RULE,
        threat=[
            {
                "framework": "MITRE ATT&CK",
                "technique": [
                    {"id": "TA0002", "name": "Execution", "subtechnique": [{"id": "x"}]}
                ],
            }
        ],
    )
    assert map_rule(raw, _url).techniques == {}
