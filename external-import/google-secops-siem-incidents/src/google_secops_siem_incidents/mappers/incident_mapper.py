"""Map a Alert + RuleMetadata to a connectors_sdk Incident."""

from datetime import datetime
from typing import Any

from connectors_sdk.models import Incident
from connectors_sdk.models.enums import IncidentType
from connectors_sdk.models.external_reference import ExternalReference
from google_secops_siem_incidents.mappers._utils import find_outcome
from google_secops_siem_incidents.models.rule_alert_response import Alert, RuleMetadata
from google_secops_siem_incidents.utils.enums import Priority, Severity


def _build_external_reference(secops_base_url: str, alert_id: str) -> ExternalReference:
    """Build an ExternalReference pointing to the alert in Google SecOps.

    Args:
        secops_base_url: Base SecOps UI URL (e.g. 'https://xxx.backstory.chronicle.security').
        alert_id: Alert identifier from the detection.

    Returns:
        ExternalReference with the constructed URL.
    """
    url = f"{secops_base_url.rstrip('/')}/alerts/{alert_id}"
    return ExternalReference(
        source_name="Google SecOps SIEM",
        description="Link to the original alert in Google SecOps SIEM.",
        url=url,
        external_id=alert_id,
    )


def _meets_severity_threshold(raw_severity: str, threshold: Severity) -> bool:
    """Check whether raw_severity meets or exceeds the configured threshold.

    Args:
        raw_severity: Severity string from the rule metadata (lowercased).
        threshold: Minimum Severity level to accept.

    Returns:
        True if the alert should be imported.
    """
    if not raw_severity:
        return True

    try:
        alert_level = Severity(
            raw_severity.upper()
        )  # pylint: disable=no-value-for-parameter
    except ValueError:
        return True
    return alert_level >= threshold


def _meets_priority_threshold(raw_priority: str, threshold: Priority) -> bool:
    """Check whether raw_priority meets or exceeds the configured threshold.

    Args:
        raw_priority: Priority string from the rule metadata.
        threshold: Minimum Priority level to accept.

    Returns:
        True if the alert should be imported.
    """
    if not raw_priority:
        return True

    try:
        alert_level = Priority(
            raw_priority.upper()
        )  # pylint: disable=no-value-for-parameter
    except ValueError:
        return True
    return alert_level >= threshold


def _filter_incident(
    severity: str | None = None,
    raw_priority: str | None = None,
    risk_score: str | None = None,
    labels: list[str] | None = None,
    severity_filter: Severity | None = None,
    priority_filter: Priority | None = None,
    risk_score_filter: int | None = None,
    tags_include: list[str] | None = None,
    tags_exclude: list[str] | None = None,
) -> bool:

    if (
        severity_filter is not None
        and severity is not None
        and not _meets_severity_threshold(severity, severity_filter)
    ):
        return False

    if (
        priority_filter is not None
        and raw_priority
        and not _meets_priority_threshold(raw_priority, priority_filter)
    ):
        return False

    if risk_score_filter is not None and risk_score is not None:
        try:
            if int(risk_score) < risk_score_filter:
                return False
        except ValueError:
            pass

    if tags_include or tags_exclude:
        alert_tags = {t.lower() for t in labels} if labels else set()

        if tags_include and not alert_tags.intersection(tags_include):
            return False

        if tags_exclude and alert_tags.intersection(tags_exclude):
            return False

    return True


def map_incident(
    alert: Alert,
    rule_metadata: RuleMetadata,
    *,
    author: Any,
    tlp_marking: Any,
    secops_base_url: str | None = None,
    severity_filter: Severity | None = None,
    priority_filter: Priority | None = None,
    risk_score_filter: int | None = None,
    tags_include: list[str] | None = None,
    tags_exclude: list[str] | None = None,
) -> Incident | None:
    """Map a alert and rule metadata to a connectors_sdk Incident.

    Args:
        alert: The detection alert.
        rule_metadata: Rule metadata associated with the alert.
        author: STIX author identity object.
        tlp_marking: TLP marking definition object.
        secops_base_url: Optional base URL for Google SecOps UI to build an external reference.
        severity_filter: Minimum Severity threshold, or None to accept all.
        priority_filter: Minimum Priority threshold, or None to accept all.
        risk_score_filter: Minimum risk score threshold, or None to accept all.
        tags_include: List of tags to include (at least one must match). Empty/None = no filter.
        tags_exclude: List of tags to exclude (any match rejects). Empty/None = no filter.

    Returns:
        Populated Incident model instance, or None if filtered out.
    """
    name_prefix = f"rule_name:{rule_metadata.properties.name} - "

    name_parts = [f"{f.name}:{f.string_val}" for f in alert.fields if f.string_val]
    name_content = ", ".join(name_parts) if name_parts else f"alert_id:{alert.id}"
    name = f"{name_prefix}{name_content}"

    raw_severity = rule_metadata.properties.metadata.get("severity", "")
    severity = raw_severity.lower() or None
    raw_priority = rule_metadata.properties.metadata.get("priority")

    incident_type = IncidentType(alert.rule_type.lower().replace("_", "-"))

    ts = alert.detection_timestamp.replace("Z", "+00:00")
    first_seen = datetime.fromisoformat(ts)
    created = first_seen

    rows: list[str] = []
    meta = rule_metadata.properties.metadata
    if meta.get("description"):
        rows.append(f"| Category | {meta['description']} |")
    if meta.get("mitre_attach_url"):
        rows.append(f"| Title | {meta['mitre_attach_url']} |")
    if raw_priority:
        rows.append(f"| Priority | {raw_priority} |")

    risk_outcome = find_outcome(alert.outcomes, "risk_score")
    risk_score = risk_outcome.int64_val if risk_outcome else None
    if risk_score is not None:
        rows.append(f"| Risk | {risk_score} |")

    description = (
        "| Attribute | Value |\n| --- | --- |\n" + "\n".join(rows) if rows else None
    )

    raw_tags = rule_metadata.properties.metadata.get("tags", "")
    labels = [t.strip() for t in raw_tags.split(",") if t.strip()] or None

    if not _filter_incident(
        severity=severity,
        raw_priority=raw_priority,
        risk_score=risk_score,
        labels=labels,
        severity_filter=severity_filter,
        priority_filter=priority_filter,
        risk_score_filter=risk_score_filter,
        tags_include=tags_include,
        tags_exclude=tags_exclude,
    ):
        return None

    last_seen = datetime.fromisoformat(
        alert.time_window.end_time.replace("Z", "+00:00")
    )

    external_references = None
    if secops_base_url:
        external_references = [_build_external_reference(secops_base_url, alert.id)]

    return Incident(
        name=name,
        severity=severity,
        incident_type=incident_type,
        first_seen=first_seen,
        last_seen=last_seen,
        created=created,
        description=description,
        labels=labels,
        author=author,
        markings=[tlp_marking],
        external_references=external_references,
    )
