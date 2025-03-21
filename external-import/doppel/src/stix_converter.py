from stix2 import Bundle, Indicator, Identity, Note, DomainName
from datetime import datetime
import uuid
from logger import get_logger

logger = get_logger(__name__)

def convert_to_stix(alert):
    try:
        # Convert 'created_at' to STIX format (ISO8601 without microseconds)
        created_at = alert.get("created_at", None)
        if created_at:
            created_at = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%f").isoformat(timespec='seconds') + "Z"

        # Generate STIX-compliant UUIDs
        alert_uuid = str(uuid.uuid4())
        identity_uuid = str(uuid.uuid4())

        # Determine Pattern (STIX requires a pattern)
        entity = alert["entity"]
        if entity.startswith("http"):  # If it's a URL
            pattern = f"[url:value = '{entity}']"
            pattern_type = "stix"
        else:  # Otherwise, it's a domain
            pattern = f"[domain-name:value = '{entity}']"
            pattern_type = "stix"

        # Indicator (Represents the threat/alert)
        indicator = Indicator(
            id=f"indicator--{alert_uuid}",
            name=alert["entity"],
            pattern=pattern,
            pattern_type=pattern_type,
            confidence=50 if alert["queue_state"] == "monitoring" else 80,
            labels=[alert["entity_state"], alert["severity"]],
            created=created_at,
            external_references=[  # Embeds External Reference inside Indicator
                {
                    "source_name": "Doppel",
                    "url": alert["doppel_link"],
                    "external_id": alert["id"]
                }
            ]
        )

        # Identity (Represents the brand/product/platform)
        identity = Identity(
            id=f"identity--{identity_uuid}",
            name=alert["brand"],
            identity_class="organization",
            sectors=[alert["product"]] if alert.get("product") else None,
            description=alert.get("platform", "No platform info provided")
        )

        # Domain Name Object (If domain info exists)
        domain_name = None
        if alert.get("entity_content") and alert["entity_content"].get("root_domain"):
            domain = alert["entity_content"]["root_domain"].get("domain")
            if domain:
                domain_name = DomainName(
                    id=f"domain-name--{uuid.uuid4()}",
                    value=domain
                )

        # Note (Contains audit logs, now referencing Indicator)
        audit_logs = alert.get("audit_logs", [])
        audit_log_entries = "\n".join([f"{log['timestamp']}: {log['type']} by {log['changed_by']}" for log in audit_logs])
        note_content = f"Audit Logs:\n{audit_log_entries}" if audit_logs else "No audit logs available."

        note = Note(
            id=f"note--{uuid.uuid4()}",
            content=note_content,
            object_refs=[indicator.id]  # Links Note to the Indicator
        )

        # Create STIX Bundle with all objects
        stix_objects = [indicator, identity, note]
        if domain_name:
            stix_objects.append(domain_name)

        stix_bundle = Bundle(objects=stix_objects).serialize()

        logger.info(f"Converted alert {alert['id']} to STIX format with UUID {alert_uuid}.")
        return stix_bundle

    except Exception as e:
        logger.error(f"Error converting to STIX: {str(e)}")
        return None
