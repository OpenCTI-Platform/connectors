"""Rule groups as returned by ``/ioarules/entities/rule-groups/v1``."""

import copy
from typing import Any

PROCESS_RULE: dict[str, Any] = {
    "instance_id": "1",
    "rulegroup_id": "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
    "name": "Encoded PowerShell (T1059.001)",
    "description": "Blocks encoded PowerShell, ATT&CK T1027.",
    "comment": "tuned after IR-42",
    "pattern_severity": "high",
    "disposition_id": 30,
    "action_label": "Kill Process",
    "ruletype_id": "1",
    "ruletype_name": "Process Creation",
    "enabled": True,
    "deleted": False,
    "created_on": "2026-01-02T03:04:05.892315096Z",
    "modified_on": "2026-09-01T10:00:00Z",
    "field_values": [
        {
            "name": "ImageFilename",
            "label": "Image Filename",
            "type": "excludable",
            "values": [{"label": "include", "value": ".*\\\\powershell\\.exe"}],
            "final_value": ".*\\\\powershell\\.exe",
        },
        {
            "name": "CommandLine",
            "label": "Command Line",
            "type": "excludable",
            "values": [{"label": "include", "value": ".*-enc.*"}],
            "final_value": ".*-enc.*",
        },
    ],
}

DNS_RULE: dict[str, Any] = {
    "instance_id": "2",
    "name": "Suspicious domain lookup",
    "description": "",
    "pattern_severity": "informational",
    "disposition_id": 20,
    "action_label": "Monitor",
    "ruletype_id": "9",
    "ruletype_name": "Domain Name",
    "enabled": False,
    "deleted": False,
    "field_values": [{"name": "DomainName", "final_value": ".*\\.example\\.com"}],
}

WINDOWS_GROUP: dict[str, Any] = {
    "id": "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
    "name": "Windows hardening",
    "platform": "windows",
    "enabled": True,
    "deleted": False,
    "rules": [PROCESS_RULE, DNS_RULE],
}

MAC_GROUP: dict[str, Any] = {
    "id": "ffeeddccbbaa99887766554433221100",
    "name": "macOS",
    "platform": "mac",
    "enabled": False,
    "deleted": False,
    "rules": [
        {
            **PROCESS_RULE,
            "instance_id": "7",
            "name": "osascript",
            "description": "",
            "ruletype_name": "Process Creation (mac)",
        }
    ],
}


def group(base: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """Return a copy of ``base`` with ``overrides`` applied."""
    value = copy.deepcopy(base)
    value.update(overrides)
    return value
