"""Alert rules as returned by the Microsoft.SecurityInsights ``alertRules`` API."""

import copy
from typing import Any

WORKSPACE_ID = (
    "/subscriptions/00000000-0000-4000-8000-0000000000cc/resourceGroups/soc-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/soc-workspace"
)

SCHEDULED_RULE: dict[str, Any] = {
    "id": f"{WORKSPACE_ID}/providers/Microsoft.SecurityInsights/alertRules/"
    "73e01a99-5cd7-4139-a149-9f2736ff2ab5",
    "name": "73e01a99-5cd7-4139-a149-9f2736ff2ab5",
    "type": "Microsoft.SecurityInsights/alertRules",
    "kind": "Scheduled",
    "etag": '"0300bf09-0000-0000-0000-5c37296e0000"',
    "systemData": {
        "createdAt": "2026-01-02T03:04:05.1234567Z",
        "lastModifiedAt": "2026-08-01T00:00:00Z",
    },
    "properties": {
        "displayName": "Encoded PowerShell",
        "description": "Detects encoded PowerShell command lines.",
        "severity": "High",
        "enabled": True,
        "tactics": ["Execution"],
        "techniques": ["T1059"],
        "subTechniques": ["T1059.001"],
        "query": 'SecurityEvent | where CommandLine has "-enc"',
        "queryFrequency": "PT1H",
        "queryPeriod": "PT1H",
        "lastModifiedUtc": "2026-09-01T10:00:00Z",
        "alertRuleTemplateName": None,
    },
}

NRT_RULE: dict[str, Any] = {
    "id": f"{WORKSPACE_ID}/providers/Microsoft.SecurityInsights/alertRules/nrt-1",
    "name": "nrt-1",
    "kind": "NRT",
    "properties": {
        "displayName": "Mass download",
        "severity": "Informational",
        "enabled": False,
        "techniques": ["T1530", "TA0010"],
        "query": "OfficeActivity | where Operation == 'FileDownloaded'",
    },
}

FUSION_RULE: dict[str, Any] = {
    "id": f"{WORKSPACE_ID}/providers/Microsoft.SecurityInsights/alertRules/BuiltInFusion",
    "name": "BuiltInFusion",
    "kind": "Fusion",
    "properties": {
        "displayName": "Advanced Multistage Attack Detection",
        "enabled": True,
        "severity": "High",
        "techniques": ["T1078"],
    },
}


def rule(base: dict[str, Any], **properties: Any) -> dict[str, Any]:
    """Return a copy of ``base`` with ``properties`` applied to its properties."""
    value = copy.deepcopy(base)
    value["properties"].update(properties)
    return value
