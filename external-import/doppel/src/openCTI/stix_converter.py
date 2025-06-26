import json
import uuid

from stix2 import Bundle, Identity, Indicator

from utils.state_handler import parse_iso_datetime

DOPPEL_IDENTITY = Identity(
    id=f"identity--{str(uuid.uuid4())}",
    name="Doppel",
    identity_class="organization",
    description="Threat Intelligence Provider",
    allow_custom=True,
)


def convert_alert_to_bundle(alerts, helper):
    stix_objects = [DOPPEL_IDENTITY]
    created_by_ref = DOPPEL_IDENTITY.id

    for alert in alerts:
        entity = alert.get("entity", "Unknown")
        pattern = f"[entity:value ='{entity}']"
        alert_id = alert.get("id", "unknown")
        alert_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"doppel-{alert_id}"))
        helper.log_info(f"Processing alert ID: {alert.get('id', 'Unknown')}")

        created_at = parse_iso_datetime(
            alert.get("created_at", ""), "created_at", alert_uuid, helper
        )
        modified = parse_iso_datetime(
            alert.get("last_activity_timestamp", ""),
            "last_activity_timestamp",
            alert_uuid,
            helper,
        )

        audit_logs = alert.get("audit_logs", [])
        audit_log_text = "\n".join(
            [
                f"{log['timestamp']}: {log['type']} - {log['value']}"
                for log in audit_logs
            ]
        )

        entity_content = alert.get("entity_content", {})
        formatted_entity_content = json.dumps(entity_content, indent=2)
        platform = alert.get("platform", "unknown")
        platform_value = alert.get("product", "Unknown")

        entity_state = alert.get("entity_state", "unknown")
        queue_state = alert.get("queue_state", "unknown")
        raw_severity = alert.get("severity", "unknown")
        severity = f"{raw_severity} severity"

        # Compose description
        description = (
            f"Platform: {platform},\n"
            f"Entity State: {entity_state},\n"
            f"Queue State: {queue_state},\n"
            f"Severity: {severity},\n"
            f"Entity Content:\n{formatted_entity_content}"
        )

        # Convert score from float (0-1) to int (0-100)
        raw_score = alert.get("score")
        try:
            score = int(float(raw_score) * 100) if raw_score is not None else 0
        except (ValueError, TypeError):
            score = 0

        indicator = Indicator(
            id=f"indicator--{alert_uuid}",
            name=entity,
            pattern=pattern,
            pattern_type="stix",
            confidence=50 if queue_state == "monitoring" else 80,
            description=description,
            created=created_at,
            modified=modified,
            created_by_ref=created_by_ref,
            external_references=[
                {
                    "source_name": DOPPEL_IDENTITY.name,
                    "url": alert.get("doppel_link"),
                    "external_id": alert.get("id"),
                }
            ],
            custom_properties={
                "x_opencti_score": score,
                "x_opencti_brand": alert.get("brand", "Unknown"),
                "x_mitre_platforms": platform_value,
                "x_opencti_source": alert.get("source", "Unknown"),
                "x_opencti_notes": alert.get("notes", ""),
                "x_opencti_audit_logs": audit_log_text,
            },
            allow_custom=True,
        )
        stix_objects.append(indicator)

    return (
        Bundle(objects=stix_objects, allow_custom=True).serialize()
        if stix_objects
        else None
    )
