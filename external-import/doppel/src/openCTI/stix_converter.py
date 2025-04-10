# src/formatters/stix_converter.py

import uuid
from datetime import datetime

from stix2 import Bundle, Identity, Indicator

from utils.state_handler import parse_iso_datetime

# Static identity object for the source
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
        pattern = f"[domain-name:value = '{entity}']"
        alert_uuid = str(uuid.uuid4())
        helper.log_info(f"Processing alert ID: {alert.get('id', 'Unknown')}")

        created_at = parse_iso_datetime(alert.get("created_at", ""), "created_at", alert_uuid, helper)
        modified = parse_iso_datetime(alert.get("last_activity_timestamp", ""), "last_activity_timestamp", alert_uuid, helper)

        audit_logs = alert.get("audit_logs", [])
        audit_log_text = "\n".join(
            [f"{log['timestamp']}: {log['type']} - {log['value']}" for log in audit_logs]
        )

        entity_content = alert.get("entity_content", {})
        entity_state = alert.get("entity_state", "unknown")
        severity = alert.get("severity", "unknown")
        queue_state = alert.get("queue_state", "unknown")
        labels = [queue_state, entity_state, severity]

        indicator = Indicator(
            id=f"indicator--{alert_uuid}",
            name=entity,
            pattern=pattern,
            pattern_type="stix",
            confidence=50 if queue_state == "monitoring" else 80,
            labels=labels,
            created=created_at,
            modified=modified,
            created_by_ref=created_by_ref,
            external_references=[
                {
                    "source_name": "Doppel",
                    "url": alert.get("doppel_link"),
                    "external_id": alert.get("id"),
                }
            ],
            custom_properties={
                "x_opencti_brand": alert.get("brand", "Unknown"),
                "x_opencti_product": alert.get("product", "Unknown"),
                "x_opencti_platform": alert.get("platform", "Unknown"),
                "x_opencti_source": alert.get("source", "Unknown"),
                "x_opencti_notes": alert.get("notes", ""),
                "x_opencti_audit_logs": audit_log_text,
                "x_opencti_entity_content": entity_content,
            },
            allow_custom=True,
        )
        stix_objects.append(indicator)

    return Bundle(objects=stix_objects, allow_custom=True).serialize() if stix_objects else None
