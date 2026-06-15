"""Converter from Corelight Investigator alerts/detections to STIX 2.1 objects."""

import ipaddress
from datetime import datetime, timezone
from typing import Optional

import stix2
from pycti import Identity, Incident, MarkingDefinition, StixCoreRelationship

_TLP_MAPPING = {
    "clear": stix2.TLP_WHITE,
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red": stix2.TLP_RED,
}

# Investigator severity is a normalized 1-10 score (10 = most critical).
_SEVERITY_BANDS = [(9, "critical"), (7, "high"), (4, "medium"), (0, "low")]

# Candidate fields that may carry source / destination IP addresses.
_SOURCE_IP_FIELDS = ("src_ip", "source_ip", "src", "id_orig_h")
_DEST_IP_FIELDS = ("dst_ip", "dest_ip", "destination_ip", "dst", "id_resp_h")


def _amber_strict() -> stix2.MarkingDefinition:
    return stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
        definition_type="statement",
        definition={"statement": "custom"},
        custom_properties={
            "x_opencti_definition_type": "TLP",
            "x_opencti_definition": "TLP:AMBER+STRICT",
        },
    )


class ConverterToStix:
    """Convert Corelight Investigator alert dictionaries into STIX 2.1 objects."""

    def __init__(self, helper, tlp_level: str):
        self.helper = helper
        self.author = self._create_author()
        if tlp_level == "amber+strict":
            self.tlp_marking = _amber_strict()
        else:
            self.tlp_marking = _TLP_MAPPING.get(tlp_level, stix2.TLP_AMBER)

    @staticmethod
    def _create_author() -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id(
                name="Corelight Investigator", identity_class="organization"
            ),
            name="Corelight Investigator",
            identity_class="organization",
            description="Alerts and detections imported from Corelight Investigator.",
        )

    @staticmethod
    def _to_iso(value) -> str:
        if value is None or value == "":
            dt = datetime.now(timezone.utc)
        elif isinstance(value, (int, float)) or (
            isinstance(value, str) and value.isdigit()
        ):
            epoch = float(value)
            if epoch > 1e12:  # milliseconds
                epoch /= 1000.0
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        else:
            try:
                dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                dt = (
                    dt.replace(tzinfo=timezone.utc)
                    if dt.tzinfo is None
                    else dt.astimezone(timezone.utc)
                )
            except ValueError:
                dt = datetime.now(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    @staticmethod
    def _map_severity(value) -> str:
        try:
            score = int(value)
        except (TypeError, ValueError):
            return "low"
        for threshold, label in _SEVERITY_BANDS:
            if score >= threshold:
                return label
        return "low"

    def create_incident(self, alert: dict) -> Optional[stix2.Incident]:
        """Create a STIX Incident from a Corelight Investigator alert/detection."""
        alert_id = str(
            alert.get("alert_id") or alert.get("id") or alert.get("uid") or ""
        ).strip()
        event_type = alert.get("EventType") or alert.get("event_type") or "Alert"
        name = (
            alert.get("name")
            or alert.get("rule_name")
            or alert.get("title")
            or (
                f"Corelight {event_type} {alert_id}"
                if alert_id
                else f"Corelight {event_type}"
            )
        )
        created = self._to_iso(
            alert.get("timestamp")
            or alert.get("ts")
            or alert.get("start_time")
            or alert.get("created")
        )
        severity = self._map_severity(alert.get("severity"))
        description = (
            alert.get("description")
            or alert.get("message")
            or "Alert imported from Corelight Investigator."
        )

        external_references = None
        if alert_id:
            external_references = [
                {"source_name": "Corelight Investigator", "external_id": alert_id}
            ]

        return stix2.Incident(
            id=Incident.generate_id(name, created),
            name=name,
            description=description,
            created=created,
            modified=created,
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking],
            external_references=external_references,
            custom_properties={
                "source": "Corelight Investigator",
                "severity": severity,
                "incident_type": str(event_type).lower(),
            },
        )

    @staticmethod
    def _ip_version(value: str) -> Optional[str]:
        try:
            return f"ipv{ipaddress.ip_address(value).version}"
        except ValueError:
            return None

    def create_observables(self, alert: dict, incident_id: str) -> list:
        """Create IP observables referenced by an alert, linked to the Incident."""
        objects = []
        seen = set()
        fields = _SOURCE_IP_FIELDS + _DEST_IP_FIELDS
        for field in fields:
            value = alert.get(field)
            if not value or not isinstance(value, str):
                continue
            value = value.strip()
            if value in seen:
                continue
            version = self._ip_version(value)
            if version is None:
                continue
            seen.add(value)

            if version == "ipv4":
                observable = stix2.IPv4Address(
                    value=value,
                    object_marking_refs=[self.tlp_marking],
                    custom_properties={"x_opencti_created_by_ref": self.author["id"]},
                )
            else:
                observable = stix2.IPv6Address(
                    value=value,
                    object_marking_refs=[self.tlp_marking],
                    custom_properties={"x_opencti_created_by_ref": self.author["id"]},
                )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", incident_id, observable["id"]
                ),
                relationship_type="related-to",
                source_ref=incident_id,
                target_ref=observable["id"],
                created_by_ref=self.author["id"],
                object_marking_refs=[self.tlp_marking],
            )
            objects.append(observable)
            objects.append(relationship)
        return objects
