from datetime import datetime, timezone

import pytest
from connector.detection_rule import RuleSkippedError
from connector.rule_mapper import logsource, map_rule, techniques
from secops_samples import (
    ARCHIVED_RULE,
    DNS_RULE,
    POWERSHELL_RULE,
    POWERSHELL_TEXT,
    deployment_of,
    rule,
)


def test_live_rule():
    mapped = map_rule(POWERSHELL_RULE, deployment_of(POWERSHELL_RULE))
    assert mapped.external_id == "ru_e6abfcb5-1b85-41b0-b64c-695b3250436f"
    assert mapped.name == "mitre_attack_T1059_001_encoded_powershell"
    assert mapped.description == "Encoded PowerShell command line"
    assert mapped.pattern == POWERSHELL_TEXT
    assert mapped.pattern_type == "yara-l"
    assert mapped.enabled is True
    assert mapped.level == "high"
    assert mapped.created_at == datetime(
        2026, 1, 2, 3, 4, 5, 123456, tzinfo=timezone.utc
    )
    assert mapped.modified_at == datetime(2026, 9, 1, 10, tzinfo=timezone.utc)
    assert mapped.logsource == {"category": "process_creation", "product": "windows"}
    assert mapped.platforms == ["windows"]
    # Technique key first, then ATT&CK links of other values, then the rule name.
    assert mapped.techniques == {"T1059.001": None, "T1027": None, "T1140": None}


def test_rule_that_is_not_live():
    mapped = map_rule(DNS_RULE, deployment_of(DNS_RULE))
    assert mapped.enabled is False
    # No severity object: the ``meta`` severity counts.
    assert mapped.level == "low"
    assert mapped.logsource == {"category": "dns_query"}
    assert mapped.platforms == []
    assert mapped.techniques == {"T1071.004": None}
    assert mapped.modified_at is None


def test_rule_without_deployment_is_not_live():
    assert map_rule(POWERSHELL_RULE, None).enabled is False
    assert map_rule(POWERSHELL_RULE, {}).enabled is False


@pytest.mark.parametrize(
    "raw_rule,deployment,reason",
    [
        (ARCHIVED_RULE, deployment_of(ARCHIVED_RULE), "archived"),
        (rule(POWERSHELL_RULE, name=None), None, "no_rule_id"),
        (rule(POWERSHELL_RULE, name="rules"), None, "no_rule_id"),
        (rule(POWERSHELL_RULE, text="  "), None, "no_text"),
        (rule(POWERSHELL_RULE, text=None), None, "no_text"),
    ],
)
def test_rules_left_out(raw_rule, deployment, reason):
    with pytest.raises(RuleSkippedError) as error:
        map_rule(raw_rule, deployment)
    assert error.value.reason == reason


def test_name_falls_back_to_meta_then_rule_id():
    nameless = rule(POWERSHELL_RULE, displayName=None)
    nameless["metadata"]["rule_name"] = "Encoded PowerShell"
    assert map_rule(nameless, None).name == "Encoded PowerShell"
    nameless["metadata"].pop("rule_name")
    assert map_rule(nameless, None).name == "ru_e6abfcb5-1b85-41b0-b64c-695b3250436f"


@pytest.mark.parametrize(
    "severity,meta_severity,level",
    [
        ({"displayName": "CRITICAL"}, None, "critical"),
        ({"displayName": "Informational"}, "High", "informational"),
        ("MEDIUM", None, "medium"),
        (None, "Info", "informational"),
        ({"displayName": "URGENT"}, "Low", "low"),
        (None, None, None),
    ],
)
def test_level(severity, meta_severity, level):
    raw_rule = rule(POWERSHELL_RULE, severity=severity, metadata={})
    if meta_severity:
        raw_rule["metadata"]["severity"] = meta_severity
    assert map_rule(raw_rule, None).level == level


@pytest.mark.parametrize(
    "metadata,display_name,expected",
    [
        # Technique keys: ids in any case, separated by commas, spaces or pipes.
        (
            {"mitre_attack_technique_id": "t1003.001 | T1003"},
            "",
            ["T1003.001", "T1003"],
        ),
        ({"TTP": "T1566;T1566.001"}, "", ["T1566", "T1566.001"]),
        # Tactics and technique names create nothing.
        (
            {
                "tactic": "TA0005",
                "mitre_attack_tactic": "Defense Evasion",
                "mitre_attack_technique": "Impair Defenses: Disable or Modify Tools",
            },
            "",
            [],
        ),
        # ATT&CK links and standalone ids in any value.
        (
            {"reference": "See https://attack.mitre.org/techniques/T1562/001/"},
            "",
            ["T1562.001"],
        ),
        ({"description": "Detects T1078 abuse"}, "", ["T1078"]),
        # Lowercase ids outside technique keys are not ids.
        ({"description": "t1078 in lowercase"}, "", []),
        # Ids embedded in the rule name.
        ({}, "mitre_attack_T1021_002_windows_admin_share", ["T1021.002"]),
        ({}, "T1105_ingress_tool_transfer", ["T1105"]),
        ({}, "rule_xT1105_or_T12345", []),
        # Duplicates are kept once, in order of appearance.
        (
            {"technique": "T1021.002", "reference": "T1021.002"},
            "mitre_attack_T1021_002",
            ["T1021.002"],
        ),
    ],
)
def test_techniques(metadata, display_name, expected):
    raw_rule = {"metadata": metadata, "displayName": display_name}
    assert list(techniques(raw_rule)) == expected


@pytest.mark.parametrize(
    "event_types,category",
    [
        (["PROCESS_LAUNCH", "PROCESS_LAUNCH"], "process_creation"),
        (["NETWORK_CONNECTION"], "network_connection"),
        (["FILE_CREATION"], "file_event"),
        (["REGISTRY_MODIFICATION"], "registry_set"),
        (["PROCESS_LAUNCH", "NETWORK_DNS"], None),
        (["USER_LOGIN"], None),
        ([], None),
    ],
)
def test_logsource_category(event_types, category):
    text = "rule r {\n  events:\n" + "".join(
        f'    $e{index}.metadata.event_type = "{event_type}"\n'
        for index, event_type in enumerate(event_types)
    )
    assert logsource({"text": text}) == ({"category": category} if category else None)


@pytest.mark.parametrize(
    "platform,product",
    [
        ("Windows", "windows"),
        ("macOS", "macos"),
        ("Mac", "macos"),
        ("AWS", "aws"),
        ("Google Workspace", "google_workspace"),
        ("Windows, Linux", None),
        ("", None),
    ],
)
def test_logsource_product(platform, product):
    result = logsource({"metadata": {"platform": platform}})
    assert result == ({"product": product} if product else None)


def test_non_dict_metadata_is_ignored():
    assert techniques({"metadata": ["T1059"], "displayName": ""}) == {}
    assert logsource({"metadata": "platform=windows"}) is None
