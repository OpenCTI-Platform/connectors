import ipaddress
import json
from typing import Literal


def detect_observable_type(
    asset_id: str,
) -> Literal["ipv4", "ipv6", "domain"] | None:
    """Classify an RF ASI asset_id as IPv4, IPv6, or domain."""
    if not asset_id or not str(asset_id).strip():
        return None

    value = str(asset_id).strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return "domain"

    if network.version == 4:
        return "ipv4"
    return "ipv6"


def build_asset_description(asset_exposure: dict) -> str | None:
    """Build an observable description from RF ASI asset exposure evidence."""
    parts: list[str] = []
    details = asset_exposure.get("details") or {}

    if target := details.get("target"):
        parts.append(f"Target: {target}")

    evidence_parts: list[str] = []
    if extractions := details.get("extractions"):
        evidence_parts.append(json.dumps(extractions, sort_keys=True))

    instances = asset_exposure.get("instances") or []
    if instances:
        instance_summaries = [
            {key: value for key, value in instance.items() if value is not None}
            for instance in instances
            if isinstance(instance, dict)
        ]
        instance_summaries = [summary for summary in instance_summaries if summary]
        if instance_summaries:
            evidence_parts.append(json.dumps(instance_summaries, sort_keys=True))

    if evidence_parts:
        parts.append(f"Evidence: {'; '.join(evidence_parts)}")

    return "\n".join(parts) if parts else None
