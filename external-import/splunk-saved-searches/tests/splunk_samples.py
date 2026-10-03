"""Entries as returned by ``/servicesNS/<owner>/<app>/saved/searches``."""

import copy
from typing import Any

API = "https://splunk.example.com:8089"

CORRELATION_SEARCH: dict[str, Any] = {
    "name": "ESCU - Windows PowerShell Encoded Command - Rule",
    "id": f"{API}/servicesNS/nobody/DA-ESS-ContentUpdate/saved/searches/"
    "ESCU%20-%20Windows%20PowerShell%20Encoded%20Command%20-%20Rule",
    "updated": "2026-09-01T10:00:00+00:00",
    "author": "nobody",
    "acl": {"app": "DA-ESS-ContentUpdate", "owner": "nobody", "sharing": "global"},
    "content": {
        "search": "| tstats count from datamodel=Endpoint.Processes "
        'where Processes.process="*-enc*" by Processes.dest',
        "description": "Detects encoded PowerShell command lines.",
        "disabled": False,
        "is_scheduled": True,
        "actions": "notable, risk",
        "action.correlationsearch.enabled": "1",
        "action.correlationsearch.label": "ESCU - Windows PowerShell Encoded Command - Rule",
        "action.correlationsearch.annotations": '{"analytic_story": ["Malicious '
        'PowerShell"], "confidence": 80, "mitre_attack": ["T1059.001", "T1027"], '
        '"type": "TTP"}',
        "action.notable.param.severity": "high",
        "alert.severity": 3,
    },
}

SCHEDULED_ALERT: dict[str, Any] = {
    "name": "Brute force on VPN (T1110)",
    "id": f"{API}/servicesNS/admin/search/saved/searches/Brute%20force%20on%20VPN",
    "updated": "2026-08-01T00:00:00+00:00",
    "acl": {"app": "search", "owner": "admin", "sharing": "app"},
    "content": {
        "search": "index=vpn action=failure | stats count by user | where count > 20",
        "description": "Password spraying, see https://attack.mitre.org/techniques/T1110/003/",
        "disabled": "1",
        "is_scheduled": "1",
        "actions": "email",
        "alert.severity": "5",
    },
}

REPORT: dict[str, Any] = {
    "name": "Weekly license usage",
    "id": f"{API}/servicesNS/nobody/search/saved/searches/Weekly%20license%20usage",
    "updated": "2026-01-01T00:00:00+00:00",
    "acl": {"app": "search", "owner": "nobody"},
    "content": {
        "search": "index=_internal source=*license_usage.log | stats sum(b)",
        "disabled": "0",
        "is_scheduled": "1",
        "actions": "",
    },
}


def entry(base: dict[str, Any], **content: Any) -> dict[str, Any]:
    """Return a copy of ``base`` with ``content`` applied to its content."""
    value = copy.deepcopy(base)
    value["content"].update(content)
    return value
