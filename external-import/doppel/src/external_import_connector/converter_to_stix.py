import json

from pycti import Identity as PyCTIIdentity
from pycti import Indicator as PyCTIIndicator
from stix2 import Bundle, Identity, Indicator

from .utils import parse_iso_datetime


class ConverterToStix:
    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        self.author = self._create_identity()

    def _create_identity(self):
        return Identity(
            id=PyCTIIdentity.generate_id(name="Doppel", identity_class="organization"),
            name="Doppel",
            identity_class="organization",
            description="Threat Intelligence Provider",
            allow_custom=True,
        )

    def convert_alerts_to_stix(self, alerts):
        stix_objects = [self.author]
        created_by_ref = self.author.id

        for alert in alerts:
            entity = alert.get("entity", "Unknown")
            pattern = f"[entity:value ='{entity}']"
            alert_id = alert.get("id", "unknown")

            # Corrected: Removed invalid keyword argument `pattern_type`
            indicator_id = PyCTIIndicator.generate_id(pattern=pattern)

            self.helper.log_info(f"Processing alert ID: {alert_id}")

            created_at = parse_iso_datetime(
                alert.get("created_at", ""), "created_at", alert_id, self.helper
            )
            modified = parse_iso_datetime(
                alert.get("last_activity_timestamp", ""),
                "last_activity_timestamp",
                alert_id,
                self.helper,
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

            description = (
                f"Platform: {platform},\n"
                f"Entity State: {entity_state},\n"
                f"Queue State: {queue_state},\n"
                f"Severity: {severity},\n"
                f"Entity Content:\n{formatted_entity_content}"
            )

            raw_score = alert.get("score")
            try:
                score = int(float(raw_score) * 100) if raw_score is not None else 0
            except (ValueError, TypeError):
                score = 0

            indicator = Indicator(
                id=indicator_id,
                name=entity,
                pattern=pattern,
                pattern_type="stix",
                description=description,
                created=created_at,
                modified=modified,
                created_by_ref=created_by_ref,
                external_references=[
                    {
                        "source_name": self.author.name,
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

        return Bundle(objects=stix_objects, allow_custom=True).serialize()
