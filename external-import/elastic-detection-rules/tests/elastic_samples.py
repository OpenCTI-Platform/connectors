"""Rules as returned by the Kibana detection engine ``_find`` API."""

import copy
from typing import Any

KUERY_RULE: dict[str, Any] = {
    "id": "6541b99a-dee9-4f6d-a86d-dbd1869d73b1",
    "rule_id": "a6542c3c-5cf6-4f51-9fd3-aa0f0a6a6e1a",
    "name": "Encoded PowerShell Command",
    "description": "Identifies PowerShell started with an encoded command.",
    "type": "query",
    "language": "kuery",
    "query": 'process.name:"powershell.exe" and process.args:"-enc"',
    "index": ["logs-endpoint.events.process-*"],
    "enabled": True,
    "severity": "high",
    "risk_score": 73,
    "created_at": "2026-01-02T03:04:05.000Z",
    "updated_at": "2026-09-01T10:00:00.000Z",
    "tags": ["Domain: Endpoint", "OS: Windows", "Tactic: Execution"],
    "threat": [
        {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0002", "name": "Execution", "reference": "x"},
            "technique": [
                {
                    "id": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "reference": "https://attack.mitre.org/techniques/T1059/",
                    "subtechnique": [
                        {
                            "id": "T1059.001",
                            "name": "PowerShell",
                            "reference": "https://attack.mitre.org/techniques/T1059/001/",
                        }
                    ],
                }
            ],
        }
    ],
}

EQL_RULE: dict[str, Any] = {
    "id": "0b9a2fd4-3f2c-4bb5-9b7e-2c4f1f0a6b11",
    "rule_id": "eql-credential-dumping",
    "name": "LSASS Memory Access",
    "description": "",
    "type": "eql",
    "query": 'process where process.name == "procdump.exe"',
    "enabled": False,
    "severity": "critical",
    "created_at": "2026-02-01T00:00:00Z",
    "updated_at": "2026-02-01T00:00:00Z",
    "tags": ["OS: Windows", "OS: Linux"],
    "threat": [
        {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0006", "name": "Credential Access"},
            "technique": [{"id": "T1003", "name": "OS Credential Dumping"}],
        },
        {"framework": "Other framework", "technique": [{"id": "T9999"}]},
    ],
}

ESQL_RULE: dict[str, Any] = {
    "id": "8b9e0c34-7c4b-4b46-9e3e-0d7e8c3a1c22",
    "rule_id": "esql-rare-process",
    "name": "Rare Process",
    "type": "esql",
    "language": "esql",
    "query": "FROM logs-* | STATS c = COUNT(*) BY process.name | WHERE c < 3",
    "enabled": True,
    "severity": "low",
    "created_at": "2026-03-01T00:00:00Z",
    "updated_at": "2026-03-01T00:00:00Z",
}

LUCENE_RULE: dict[str, Any] = {
    "id": "1c4e2a77-63a4-4b0e-8d3b-6a3a3b2c1d33",
    "rule_id": "lucene-failures",
    "name": "Authentication Failure",
    "type": "query",
    "language": "lucene",
    "query": "event.outcome:failure",
    "enabled": True,
    "severity": "medium",
}

THRESHOLD_RULE: dict[str, Any] = {
    "id": "5a8c6e11-07b8-4f42-8c7f-0e7e7f6a5b77",
    "rule_id": "kuery-brute-force",
    "name": "Brute Force",
    "type": "threshold",
    "language": "kuery",
    "query": "event.category:authentication and event.outcome:failure",
    "threshold": {
        "field": ["source.ip", "user.name"],
        "value": 5,
        "cardinality": [{"field": "host.name", "value": 2}],
    },
    "enabled": True,
    "severity": "medium",
}

NEW_TERMS_RULE: dict[str, Any] = {
    "id": "6b9d7f22-18c9-4053-9d80-1f8f8a7b6c88",
    "rule_id": "new-terms-admin",
    "name": "First Time Seen Administrator Logon",
    "type": "new_terms",
    "language": "kuery",
    "query": "event.category:authentication and user.roles:admin",
    "new_terms_fields": ["user.name", "host.name"],
    "history_window_start": "now-14d",
    "enabled": True,
    "severity": "low",
}

THREAT_MATCH_RULE: dict[str, Any] = {
    "id": "7cae8033-29da-4164-ae91-2090ab8c7d99",
    "rule_id": "indicator-match-ip",
    "name": "Threat Intel IP Address Indicator Match",
    "type": "threat_match",
    "language": "kuery",
    "query": "destination.ip:*",
    "threat_query": "threat.indicator.type:ipv4-addr",
    "threat_language": "kuery",
    "threat_index": ["filebeat-*", "logs-ti_*"],
    "threat_mapping": [
        {
            "entries": [
                {
                    "field": "destination.ip",
                    "type": "mapping",
                    "value": "threat.indicator.ip",
                }
            ]
        }
    ],
    "threat_indicator_path": "threat.indicator",
    "items_per_search": 100,
    "enabled": True,
    "severity": "high",
}

ML_RULE: dict[str, Any] = {
    "id": "2d5f3b88-74b5-4c1f-9e4c-7b4b4c3d2e44",
    "rule_id": "ml-rare-logon",
    "name": "Unusual Logon",
    "type": "machine_learning",
    "anomaly_threshold": 50,
    "machine_learning_job_id": ["auth_rare_user"],
    "enabled": True,
    "severity": "low",
}


def rule(base: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """Return a copy of ``base`` with ``overrides`` applied."""
    value = copy.deepcopy(base)
    value.update(overrides)
    return value
