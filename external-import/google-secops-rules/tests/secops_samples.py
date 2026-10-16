"""Rules and rule deployments as returned by the Chronicle API."""

import copy
from typing import Any

INSTANCE = "projects/soc-project/locations/europe/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6"

POWERSHELL_TEXT = """rule mitre_attack_T1059_001_encoded_powershell {
  meta:
    author = "SOC"
    description = "Encoded PowerShell command line"
    severity = "High"
    technique = "T1059.001, T1027"
    reference = "https://attack.mitre.org/techniques/T1140/"
    platform = "Windows"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.command_line = /-enc/ nocase
  condition:
    $e
}
"""

POWERSHELL_RULE: dict[str, Any] = {
    "name": f"{INSTANCE}/rules/ru_e6abfcb5-1b85-41b0-b64c-695b3250436f",
    "revisionId": "v_1767323045_123456000",
    "displayName": "mitre_attack_T1059_001_encoded_powershell",
    "text": POWERSHELL_TEXT,
    "author": "SOC",
    "severity": {"displayName": "HIGH"},
    "metadata": {
        "author": "SOC",
        "description": "Encoded PowerShell command line",
        "severity": "High",
        "technique": "T1059.001, T1027",
        "reference": "https://attack.mitre.org/techniques/T1140/",
        "platform": "Windows",
    },
    "createTime": "2026-01-02T03:04:05.123456789Z",
    "revisionCreateTime": "2026-09-01T10:00:00Z",
    "compilationState": "SUCCEEDED",
    "type": "SINGLE_EVENT",
}

DNS_TEXT = """rule dns_tunneling_long_queries {
  meta:
    description = "Many long DNS queries from one host"
    severity = "Low"
    mitre_attack_tactic = "Command and Control"
    mitre_attack_url = "https://attack.mitre.org/techniques/T1071/004/"
  events:
    $dns.metadata.event_type = "NETWORK_DNS"
    $dns.principal.hostname = $host
  match:
    $host over 1h
  condition:
    #dns > 500
}
"""

DNS_RULE: dict[str, Any] = {
    "name": f"{INSTANCE}/rules/ru_0b8ad7d2-2f0e-4c2a-9d1b-7d7c3a0f5e21",
    "displayName": "dns_tunneling_long_queries",
    "text": DNS_TEXT,
    "metadata": {
        "description": "Many long DNS queries from one host",
        "severity": "Low",
        "mitre_attack_tactic": "Command and Control",
        "mitre_attack_url": "https://attack.mitre.org/techniques/T1071/004/",
    },
    "createTime": "2026-03-04T05:06:07Z",
    "type": "MULTI_EVENT",
}

ARCHIVED_RULE: dict[str, Any] = {
    "name": f"{INSTANCE}/rules/ru_7c1d9e2a-0f3b-4b8e-a6c5-1e2d3f4a5b6c",
    "displayName": "old_rule",
    "text": 'rule old_rule {\n  events:\n    $e.metadata.event_type = "USER_LOGIN"\n'
    "  condition:\n    $e\n}\n",
    "createTime": "2025-01-01T00:00:00Z",
}

DEPLOYMENTS: list[dict[str, Any]] = [
    {
        "name": f"{POWERSHELL_RULE['name']}/deployment",
        "enabled": True,
        "alerting": True,
        "runFrequency": "LIVE",
        "executionState": "DEFAULT",
    },
    {
        "name": f"{DNS_RULE['name']}/deployment",
        "enabled": False,
        "alerting": False,
        "runFrequency": "HOURLY",
    },
    {
        "name": f"{ARCHIVED_RULE['name']}/deployment",
        "archived": True,
        "archiveTime": "2026-02-01T00:00:00Z",
    },
]


def deployment_of(rule: dict[str, Any]) -> dict[str, Any]:
    """Return the sample deployment of ``rule``."""
    return next(d for d in DEPLOYMENTS if d["name"] == f"{rule['name']}/deployment")


def rule(base: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """Return a copy of ``base`` with ``overrides`` applied."""
    value = copy.deepcopy(base)
    value.update(overrides)
    return value
