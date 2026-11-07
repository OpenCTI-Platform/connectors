"""Envelope mapping shared by every Vision service."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from connectors_sdk.models import (
    ExternalReference,
    OrganizationAuthor,
    TLPMarking,
)
from connectors_sdk.models.enums import IncidentSeverity

SEVERITY_MAP = {
    "LOW": IncidentSeverity.LOW,
    "MEDIUM": IncidentSeverity.MEDIUM,
    "HIGH": IncidentSeverity.HIGH,
    "CRITICAL": IncidentSeverity.CRITICAL,
}

_TIMESTAMP_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d+))?"
    r"(?P<offset>Z|[+-]\d{2}:?\d{2})?$"
)


def parse_datetime(value: Any) -> datetime | None:
    """Parse a Vision timestamp into a timezone-aware datetime."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    match = _TIMESTAMP_RE.match(str(value).strip())
    if not match:
        raise ValueError(f"Unrecognised Vision timestamp: {value!r}")

    text = match.group("base")
    if fraction := match.group("fraction"):
        text += f".{fraction[:6]}"

    offset = match.group("offset")
    if offset in (None, "Z"):
        text += "+00:00"
    elif ":" not in offset:
        text += f"{offset[:3]}:{offset[3:]}"
    else:
        text += offset

    return datetime.fromisoformat(text)


def extract_payload(alert: dict[str, Any]) -> dict[str, Any]:
    """Return the usable content dict for a Vision alert.

    Services are inconsistent. Some nest a dict at ``data.data``, some put
    the real fields on ``data`` itself, and some store a primitive (CVE id,
    subdomain, credential line) at ``data.data``.
    """
    data = alert.get("data")
    if not isinstance(data, dict):
        return {}

    inner = data.get("data")
    if isinstance(inner, dict):
        return inner

    outer = {key: value for key, value in data.items() if key != "data"}
    if outer:
        if inner is not None:
            outer["value"] = inner
        return outer
    if inner is not None:
        return {"value": inner}
    return {}


def first_text(*values: Any) -> str | None:
    """Return the first non-empty string among the given values."""
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def labeled(label: str, value: Any) -> str | None:
    """Return ``Label: value`` when value is non-empty."""
    text = first_text(value)
    return f"{label}: {text}" if text else None


def description_lines(*parts: Any) -> str | None:
    """Join non-empty description parts with newlines."""
    lines = []
    for part in parts:
        if part is None:
            continue
        text = str(part).strip()
        if text:
            lines.append(text)
    return "\n".join(lines) if lines else None


@dataclass
class AlertContext:
    """Everything derived from the stable outer fields of an alert."""

    alert_id: str
    service: str
    author: OrganizationAuthor
    markings: list[TLPMarking]
    labels: list[str]
    external_references: list[ExternalReference]
    severity: IncidentSeverity | None
    created: datetime | None
    updated: datetime | None
    asset: str | None
    description: str | None
    raw: dict[str, Any]

    def entity_kwargs(self) -> dict[str, Any]:
        return {
            "author": self.author,
            "markings": self.markings,
            "labels": self.labels,
            "external_references": self.external_references,
            "created": self.created,
        }

    def observable_kwargs(self) -> dict[str, Any]:
        return {
            "author": self.author,
            "markings": self.markings,
            "external_references": self.external_references,
        }


def build_context(
    alert: dict[str, Any],
    author: OrganizationAuthor,
    marking: TLPMarking,
    portal_url_template: str,
) -> AlertContext:
    """Map the stable envelope fields of any Vision alert."""
    service = alert["service"]
    raw_severity = alert.get("user_severity") or alert.get("severity")
    severity = SEVERITY_MAP.get(str(raw_severity).upper()) if raw_severity else None

    labels = ["cyble", f"cyble:{service}"]
    labels += [t for t in (alert.get("tags") or []) if t]
    if alert.get("bucket_name"):
        labels.append(f"cyble:bucket:{alert['bucket_name']}")

    deep_link = portal_url_template.format(service=service, alert_id=alert["id"])
    reference = ExternalReference(
        source_name="Cyble Vision",
        url=deep_link,
        external_id=alert["id"],
        description=f"Cyble Vision alert ({service})",
    )

    return AlertContext(
        alert_id=alert["id"],
        service=service,
        author=author,
        markings=[marking],
        labels=labels,
        external_references=[reference],
        severity=severity,
        created=parse_datetime(alert.get("created_at")),
        updated=parse_datetime(alert.get("updated_at")),
        asset=alert.get("asset") or alert.get("keyword_name"),
        description=alert.get("description"),
        raw=alert,
    )
