import json

from doppel.utils import parse_iso_datetime
from pycti import Identity as PyCTIIdentity
from pycti import Indicator as PyCTIIndicator
from pycti import MarkingDefinition
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE, Identity, Indicator
from stix2 import MarkingDefinition as Stix2MarkingDefinition


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        self.author = self._create_identity()
        self.tlp_marking = self._create_tlp_marking(level=self.config.tlp_level.lower())

    def _create_identity(self) -> Identity:
        """
        Create Identity
        :return: Identity Stix2 object
        """
        return Identity(
            id=PyCTIIdentity.generate_id(name="Doppel", identity_class="organization"),
            name="Doppel",
            identity_class="organization",
            description="Threat Intelligence Provider",
            allow_custom=True,
        )

    @staticmethod
    def _create_tlp_marking(level: str) -> Stix2MarkingDefinition:
        """
        Create TLP marking
        :return: Stix2 MarkingDefinition object
        """
        mapping = {
            "white": TLP_WHITE,
            "clear": TLP_WHITE,
            "green": TLP_GREEN,
            "amber": TLP_AMBER,
            "amber+strict": Stix2MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": TLP_RED,
        }
        return mapping[level]

    def convert_alerts_to_stix(self, alerts: list):
        """
        Convert list of alerts to stix2 Indicator objects
        :return: stix2 bundle json
        """
        stix_objects = [self.author, self.tlp_marking]
        created_by_ref = self.author.id

        for alert in alerts:
            alert_id = alert.get("id", "unknown")
            self.helper.connector_logger.info(
                "Processing alert", {"alert_id": alert_id}
            )

            entity = alert.get("entity", "unknown")
            pattern = f"[entity:value ='{entity}']"
            indicator_id = PyCTIIndicator.generate_id(pattern=pattern)

            created_at = (
                parse_iso_datetime(alert["created_at"])
                if alert.get("created_at", None)
                else None
            )

            modified = (
                parse_iso_datetime(alert["last_activity_timestamp"])
                if alert.get("last_activity_timestamp", None)
                else None
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
            platform_value = alert.get("product", "unknown")

            entity_state = alert.get("entity_state", "unknown")
            queue_state = alert.get("queue_state", "unknown")
            raw_severity = alert.get("severity", "unknown")
            severity = f"{raw_severity} severity"

            description = (
                f"**Platform**: {platform}  \n"
                f"**Entity State**: {entity_state}  \n"
                f"**Queue State**: {queue_state}  \n"
                f"**Severity**: {severity}  \n"
                f"**Entity Content**:  \n"
                f"{formatted_entity_content}"
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
                object_marking_refs=[self.tlp_marking["id"]],
                external_references=[
                    {
                        "source_name": self.author.name,
                        "url": alert.get("doppel_link"),
                        "external_id": alert.get("id"),
                    }
                ],
                custom_properties={
                    "x_opencti_score": score,
                    "x_opencti_brand": alert.get("brand", "unknown"),
                    "x_mitre_platforms": platform_value,
                    "x_opencti_source": alert.get("source", "unknown"),
                    "x_opencti_notes": alert.get("notes", ""),
                    "x_opencti_audit_logs": audit_log_text,
                },
                allow_custom=True,
            )
            stix_objects.append(indicator)

        return self.helper.stix2_create_bundle(stix_objects)
