import json
from datetime import datetime, timezone

import pytest
from connector.detection_rule import RuleSkippedError
from connector.rule_mapper import (
    ANNOTATIONS_KEY,
    annotation_techniques,
    in_scope,
    is_running,
    is_true,
    map_saved_search,
    saved_search_id,
)
from splunk_samples import CORRELATION_SEARCH, REPORT, SCHEDULED_ALERT, entry

ANNOTATED = '{"mitre_attack": ["T1078"]}'


def _url(raw):
    return f"https://web/{raw['name']}"


@pytest.mark.parametrize(
    "value,expected",
    [
        (True, True),
        (False, False),
        (1, True),
        (0, False),
        ("1", True),
        ("0", False),
        ("true", True),
        ("False", False),
        (None, False),
        ("", False),
    ],
)
def test_is_true(value, expected):
    assert is_true(value) is expected


@pytest.mark.parametrize(
    "raw,scope,expected",
    [
        (CORRELATION_SEARCH, "correlation_searches", True),
        (SCHEDULED_ALERT, "correlation_searches", False),
        (SCHEDULED_ALERT, "alerts", True),
        (REPORT, "alerts", False),
        (entry(REPORT, **{"alert.track": "1"}), "alerts", True),
        (entry(SCHEDULED_ALERT, is_scheduled="0"), "alerts", False),
        (REPORT, "all", True),
        # Saved searches annotated with ATT&CK techniques are detections.
        (entry(REPORT, **{ANNOTATIONS_KEY: ANNOTATED}), "alerts", True),
        (entry(REPORT, **{ANNOTATIONS_KEY: ANNOTATED}), "correlation_searches", False),
        (entry(REPORT, **{ANNOTATIONS_KEY: '{"mitre_attack": []}'}), "alerts", False),
        (
            entry(REPORT, **{ANNOTATIONS_KEY: '{"mitre_attack": ["TA0002"]}'}),
            "alerts",
            False,
        ),
    ],
)
def test_scope(raw, scope, expected):
    assert in_scope(raw["content"], scope) is expected


@pytest.mark.parametrize(
    "disabled,is_scheduled,running",
    [
        (False, True, True),
        ("0", "1", True),
        ("1", "1", False),
        (False, False, False),
        (False, None, False),
    ],
)
def test_only_enabled_scheduled_searches_run(disabled, is_scheduled, running):
    raw = entry(CORRELATION_SEARCH, disabled=disabled, is_scheduled=is_scheduled)
    assert is_running(raw["content"]) is running
    assert map_saved_search(raw, "all", _url).enabled is running


def test_correlation_search():
    rule = map_saved_search(CORRELATION_SEARCH, "alerts", _url)
    assert rule.external_id == (
        "DA-ESS-ContentUpdate/nobody/ESCU - Windows PowerShell Encoded Command - Rule"
    )
    assert rule.name == "ESCU - Windows PowerShell Encoded Command - Rule"
    assert rule.pattern == CORRELATION_SEARCH["content"]["search"]
    assert rule.pattern_type == "spl"
    assert rule.enabled is True
    # The notable event severity wins over alert.severity.
    assert rule.level == "high"
    assert rule.techniques == {"T1059.001": None, "T1027": None}
    assert rule.created_at is None
    assert rule.modified_at == datetime(2026, 9, 1, 10, tzinfo=timezone.utc)
    assert rule.url == f"https://web/{CORRELATION_SEARCH['name']}"


def test_trigger_condition_is_part_of_the_pattern():
    raw = entry(CORRELATION_SEARCH, alert_threshold="10")
    rule = map_saved_search(raw, "alerts", _url)
    assert rule.pattern_type == "splunk-rule"
    assert json.loads(rule.pattern) == {
        "search": CORRELATION_SEARCH["content"]["search"],
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "10",
    }


def test_custom_trigger_condition_is_part_of_the_pattern():
    raw = entry(
        CORRELATION_SEARCH,
        alert_type="custom",
        alert_condition="search count > 5",
    )
    pattern = json.loads(map_saved_search(raw, "alerts", _url).pattern)
    assert pattern["alert_type"] == "custom"
    assert pattern["alert_condition"] == "search count > 5"


def test_trigger_change_changes_the_pattern():
    patterns = {
        map_saved_search(entry(CORRELATION_SEARCH, **trigger), "alerts", _url).pattern
        for trigger in (
            {},
            {"alert_threshold": "10"},
            {"alert_threshold": "20"},
            {"alert_type": "number of hosts"},
            {"alert_comparator": "rises by", "alert_threshold": "10"},
        )
    }
    assert len(patterns) == 5


@pytest.mark.parametrize(
    "trigger",
    [
        {"alert_type": "always", "alert_threshold": "10"},
        {"alert_type": None, "alert_comparator": None, "alert_threshold": None},
        {"alert_condition": "search count > 5"},
    ],
)
def test_triggers_alerting_on_any_result_keep_the_search(trigger):
    rule = map_saved_search(entry(CORRELATION_SEARCH, **trigger), "alerts", _url)
    assert (rule.pattern_type, rule.pattern) == (
        "spl",
        CORRELATION_SEARCH["content"]["search"],
    )


def test_scheduled_alert_without_annotations():
    rule = map_saved_search(SCHEDULED_ALERT, "alerts", _url)
    assert rule.enabled is False
    assert rule.level == "high"
    # Technique ids written in the name and description (link included).
    assert rule.techniques == {"T1110": None, "T1110.003": None}


@pytest.mark.parametrize(
    "annotations",
    ["", "not json", '["T1059"]', '{"mitre_attack": "T1059"}'],
)
def test_annotations_variants(annotations):
    raw = entry(
        CORRELATION_SEARCH,
        **{"action.correlationsearch.annotations": annotations},
    )
    techniques = map_saved_search(raw, "all", _url).techniques
    expected = {"T1059": None} if "mitre_attack" in annotations else {}
    assert techniques == expected


@pytest.mark.parametrize(
    "annotations,expected",
    [
        ('{"mitre_attack": ["T1059.001", "T1027"]}', ["T1059.001", "T1027"]),
        (
            '{"mitre_attack": "T1059.001, t1027 | T1105"}',
            ["T1059.001", "T1027", "T1105"],
        ),
        (
            '{"mitre_attack": ["https://attack.mitre.org/techniques/T1021/002/"]}',
            ["T1021.002"],
        ),
        ('{"mitre_attack": ["T1059.001", "T1059.001"]}', ["T1059.001"]),
        ('{"mitre_attack": {"id": "T1059"}}', []),
        ('{"mitre_attack": ["TA0002", "Execution"]}', []),
        ({"mitre_attack": ["T1566"]}, ["T1566"]),
        (None, []),
    ],
)
def test_annotation_techniques(annotations, expected):
    assert list(annotation_techniques(annotations)) == expected


def test_annotated_report_is_imported_but_not_active():
    raw = entry(REPORT, is_scheduled="0", **{ANNOTATIONS_KEY: ANNOTATED})
    rule = map_saved_search(raw, "alerts", _url)
    assert rule.techniques == {"T1078": None}
    assert rule.enabled is False


def test_annotations_as_an_object_and_label_fallback():
    raw = entry(
        CORRELATION_SEARCH,
        **{
            "action.correlationsearch.annotations": {
                "mitre_attack": ["t1003", "TA0006"]
            },
            "action.correlationsearch.label": "",
        },
    )
    rule = map_saved_search(raw, "all", _url)
    assert rule.techniques == {"T1003": None}
    assert rule.name == CORRELATION_SEARCH["name"]


@pytest.mark.parametrize(
    "severity,expected",
    [("1", "informational"), (4, "medium"), ("6", "critical"), ("x", None), (9, None)],
)
def test_alert_severity_levels(severity, expected):
    raw = entry(SCHEDULED_ALERT, **{"alert.severity": severity})
    assert map_saved_search(raw, "all", _url).level == expected


@pytest.mark.parametrize(
    "raw,scope,reason",
    [
        (REPORT, "alerts", "out_of_scope"),
        ({**CORRELATION_SEARCH, "name": ""}, "all", "no_name"),
        (entry(CORRELATION_SEARCH, search=" "), "all", "no_query"),
    ],
)
def test_saved_searches_left_out(raw, scope, reason):
    with pytest.raises(RuleSkippedError) as error:
        map_saved_search(raw, scope, _url)
    assert error.value.reason == reason


def test_saved_search_id():
    assert saved_search_id("search", "admin", "a/b search") == "search/admin/a/b search"


def test_same_name_in_two_namespaces_gets_two_ids():
    other_app = {
        **CORRELATION_SEARCH,
        "acl": {"app": "SA-Custom", "owner": "admin", "sharing": "app"},
    }
    ids = {
        map_saved_search(raw, "alerts", _url).external_id
        for raw in (CORRELATION_SEARCH, other_app)
    }
    assert ids == {
        f"DA-ESS-ContentUpdate/nobody/{CORRELATION_SEARCH['name']}",
        f"SA-Custom/admin/{CORRELATION_SEARCH['name']}",
    }


def test_missing_acl_uses_wildcard_namespaces():
    raw = {key: value for key, value in CORRELATION_SEARCH.items() if key != "acl"}
    rule = map_saved_search(raw, "alerts", _url)
    assert rule.external_id == f"-/-/{CORRELATION_SEARCH['name']}"
