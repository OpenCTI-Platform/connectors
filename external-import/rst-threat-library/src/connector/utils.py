"""Shared connector helpers."""

from __future__ import annotations

from typing import Any, Dict, List


class ThreatObjectType:
    INTRUSION_SETS = "intrusion-sets"
    MALWARE = "malware"
    TOOLS = "tools"
    CAMPAIGNS = "campaigns"


PATH_TO_STIX_TYPE = {
    ThreatObjectType.INTRUSION_SETS: "intrusion-set",
    ThreatObjectType.MALWARE: "malware",
    ThreatObjectType.TOOLS: "tool",
    ThreatObjectType.CAMPAIGNS: "campaign",
}

ENTITY_TYPE_TO_STIX = {
    "Intrusion-Set": "intrusion-set",
    "Malware": "malware",
    "Tool": "tool",
    "Campaign": "campaign",
}


def with_sync_labels(item: Dict[str, Any], sync_labels: List[str]) -> Dict[str, Any]:
    if not sync_labels:
        return item
    out = dict(item)
    labels = list(out.get("objectLabel") or [])
    for label in sync_labels:
        if label not in labels:
            labels.append(label)
    out["objectLabel"] = labels
    return out
