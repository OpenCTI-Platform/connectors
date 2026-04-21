import base64
from datetime import datetime, timezone
from typing import Literal

import stix2
from pycti import Identity, MarkingDefinition, OpenCTIConnectorHelper, Incident


class ConverterToStix:
    """
    Provides methods for converting BitSight alert data into STIX 2.1 objects.

    REQUIREMENTS:
        - `generate_id()` methods from `pycti` library MUST be used to generate the `id` of each entity,
        e.g. `pycti.Identity.generate_id(name="Source Name", identity_class="organization")`.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
    ):
        self.helper = helper
        self.author = self._create_author()
        self.tlp_marking = self._create_tlp_marking(level=tlp_level.lower())

    @staticmethod
    def _create_author() -> dict:
        """Create the BitSight author identity."""
        return stix2.Identity(
            id=Identity.generate_id(name="BitSight", identity_class="organization"),
            name="BitSight",
            identity_class="organization",
            description="BitSight threat intelligence provider.",
            external_references=[
                stix2.ExternalReference(
                    source_name="BitSight",
                    url="https://www.bitsighttech.com",
                    description="BitSight threat intelligence platform.",
                )
            ],
        )

    @staticmethod
    def _create_tlp_marking(level: str):
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[level]

    @staticmethod
    def _convert_actor_information_to_markdown_content(alert: dict) -> str:
        markdown_content = (
            "### Actor information \n"
            f"- **Actor Name**: {alert.get('actor_information').get('actor_name')} \n"
            f"- **Actor Reputation**: {alert.get('actor_information').get('reputation')} \n"
            f"- **Actor Site**: {alert.get('actor_information').get('site')} \n"
            f"- **Actor Language(s)**: {", ".join(alert.get('actor_information').get('languages'))} \n"
            f"- **Actor Activity**: {alert.get('actor_information').get('activity')} \n"
        )
        return markdown_content

    @staticmethod
    def _convert_site_information_to_markdown_content(alert: dict) -> str:
        markdown_content = (
            "### Site information \n"
            f"- **Site Name**: {alert.get('actor_information').get('site_name')} \n"
            f"- **Site Type**: {alert.get('actor_information').get('type')} \n"
            f"- **Site Description**: {alert.get('actor_information').get('description')} \n"
            f"- **Site Active Since**: {alert.get('actor_information').get('active_since')} \n"
            f"- **Site Stars**: {alert.get('actor_information').get('stars')} \n"
            f"- **Site Language(s)**: {", ".join(alert.get('actor_information').get('languages'))} \n"
        )
        return markdown_content

    def _convert_alert_to_markdown_content(self, alert: dict) -> str:
        """
        Create a Markdown content representing an Alert from Flashpoint.
        :param alert: A Flashpoint alert to convert into Markdown.
        :return: Markdown as string
        """
        markdown_content = (
            "### Metadata \n"
            f"- **Alert Id**: {alert.get('alert_id')}  \n"
            f"- **Created**: {alert.get('create_time')}  \n"
            f"- **Updated**: {alert.get('update_time')}  \n"
            f"- **Title**: {alert.get('title')}  \n"
            f"- **Threat Level**: {", ".join(alert.get('threats')) }\n"
            f"- **Threats**: {alert.get('threat_level')}  \n"
            " \n"
            "### Description \n"
            f"{alert.get('description')} \n"
            "### Assessment \n"
            f"{alert.get('assessment') or 'N/A'} \n"
            "### Summary \n"
            f"{alert.get('summary') or 'N/A'} \n"
            "### Recommendations \n"
            + "".join(f"- {r}\n" for r in (alert.get("recommendations") or []))
        )

        if alert.get("actor_information"):
            markdown_content += (
                self._convert_actor_information_to_markdown_content(alert)
            )
        if alert.get("site_information"):
            markdown_content += (
                self._convert_actor_information_to_markdown_content(alert)
            )
        return markdown_content

    def create_incident_from_alert(self, alert_detail: dict) -> stix2.Incident | None:
        """
        Convert a BitSight alert detail into a STIX Incident object.

        :param alert_detail: Alert detail dict from the API
        :return: STIX Incident object or None if data is insufficient
        """
        import json
        print(json.dumps(alert_detail))
        alert_id = alert_detail.get("id", "unknown")
        incident_name = alert_detail.get("title", alert_detail.get("title", f"BitSight Alert {alert_id}"))
        description = alert_detail.get("description", "No description available.")
        created = self._parse_datetime(alert_detail.get("create_time"))
        modified = self._parse_datetime(alert_detail.get("update_time"))
        threats = alert_detail.get("threats") or []
        incident_type = threats[0] if threats else ""
        severity = alert_detail.get("severity", None)

        custom_properties = {
            "x_opencti_created_by_ref": self.author["id"],
        }
        if severity:
            custom_properties["x_opencti_severity"] = severity

        # generate octi incident id
        incident_id = Incident.generate_id(
            name=incident_name, created=created
        )

        # generate a content based on alert useful information
        markdown_content = self._convert_alert_to_markdown_content(alert_detail)

        # add the alert formatted content into a file attached to the incident
        files = []
        markdown_content_bytes = markdown_content.encode("utf-8")
        base64_bytes = base64.b64encode(markdown_content_bytes)
        files.append(
            {
                "name": "alert.md",
                "data": base64_bytes,
                "mime_type": "text/markdown",
                "no_trigger_import": False,
            }
        )
        custom_properties["x_opencti_files"] = files

        try:
            incident = stix2.Incident(
                id=incident_id,
                name=incident_name,
                description=description,
                incident_type=incident_type,
                created=created,
                modified=modified,
                first_seen=created,
                created_by_ref=self.author["id"],
                object_marking_refs=[self.tlp_marking["id"]],
                custom_properties=custom_properties,
                allow_custom=True,
            )
            return incident

        except Exception as err:
            self.helper.connector_logger.error(
                "[CONVERTER] Failed to create incident from alert",
                {"alert_id": alert_id, "error": str(err)},
            )
            return None

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime | None:
        """Parse a date string in format 'YYYY-MM-DD HH:MM:SS' to a datetime object."""
        if not value:
            return None
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except (ValueError, TypeError):
            return None
