"""Converter from ArcSight ESM cases to STIX 2.1 objects."""

from datetime import datetime, timezone
from typing import Optional

import stix2
from pycti import (
    CaseIncident,
    CustomObjectCaseIncident,
    Identity,
    Incident,
    MarkingDefinition,
)

_TLP_MAPPING = {
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red": stix2.TLP_RED,
}

# ArcSight exposes case severity as a 0-10 number; map it to OpenCTI severity.
_SEVERITY_BANDS = [
    (9, "critical"),
    (7, "high"),
    (4, "medium"),
    (0, "low"),
]

# OpenCTI case priority derived from the severity.
_PRIORITY_MAPPING = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}


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


def _clear() -> stix2.MarkingDefinition:
    # TLP:CLEAR is a distinct OpenCTI marking (custom statement marking with
    # x_opencti_definition="TLP:CLEAR"), not an alias of STIX TLP:WHITE.
    return stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
        definition_type="statement",
        definition={"statement": "custom"},
        custom_properties={
            "x_opencti_definition_type": "TLP",
            "x_opencti_definition": "TLP:CLEAR",
        },
    )


class ConverterToStix:
    """Convert ArcSight ESM case dictionaries into STIX 2.1 objects."""

    def __init__(self, helper, tlp_level: str):
        self.helper = helper
        self.author = self._create_author()
        if tlp_level == "amber+strict":
            self.tlp_marking = _amber_strict()
        elif tlp_level == "clear":
            self.tlp_marking = _clear()
        else:
            self.tlp_marking = _TLP_MAPPING.get(tlp_level, stix2.TLP_AMBER)

    @staticmethod
    def _create_author() -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id(name="ArcSight", identity_class="organization"),
            name="ArcSight",
            identity_class="organization",
            description="Cases imported from ArcSight ESM.",
        )

    @staticmethod
    def _to_iso(value) -> str:
        """
        Best-effort conversion of an ArcSight timestamp to a STIX-compatible UTC
        timestamp string (millisecond precision, ``Z`` suffix).
        """
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
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in ("low", "medium", "high", "critical"):
                return lowered
            if lowered.isdigit():
                value = int(lowered)
        if isinstance(value, (int, float)):
            for threshold, label in _SEVERITY_BANDS:
                if value >= threshold:
                    return label
        return "low"

    def create_incident(self, event: dict) -> Optional[stix2.Incident]:
        """
        Create a STIX Incident from an ArcSight security event.

        ArcSight security events are detections/alerts, so they map to an OpenCTI
        Incident (the case that groups them is modeled as a Case-Incident).
        """
        event_id = str(event.get("eventId") or event.get("id") or "").strip()
        if not event_id:
            base = event.get("baseEventIds")
            if isinstance(base, list) and base:
                event_id = str(base[0])
            elif base:
                event_id = str(base)

        name = event.get("name") or (
            f"ArcSight event {event_id}" if event_id else "ArcSight event"
        )
        created = self._to_iso(
            event.get("endTime")
            or event.get("startTime")
            or event.get("managerReceiptTime")
        )
        severity = self._map_severity(event.get("priority", event.get("agentSeverity")))
        description = (
            event.get("message") or "Security event imported from ArcSight ESM."
        )

        external_references = None
        if event_id:
            external_references = [
                {"source_name": "ArcSight ESM", "external_id": event_id}
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
                "source": "ArcSight ESM",
                "severity": severity,
                "incident_type": "alert",
            },
        )

    def create_case_incident(
        self, case: dict, object_refs=None
    ) -> Optional[CustomObjectCaseIncident]:
        """
        Create a STIX Case-Incident from an ArcSight case dictionary.

        ArcSight cases are case-management artifacts, so they map to an OpenCTI
        Case-Incident (not an Incident, which is reserved for alerts/detections).
        The referenced security events are modeled as Incidents linked through
        ``object_refs``.
        """
        name = case.get("name") or "ArcSight Case"
        external_id = str(
            case.get("resourceid") or case.get("id") or case.get("uri") or ""
        ).strip()
        created = self._to_iso(case.get("createdTimestamp") or case.get("createTime"))
        modified = self._to_iso(
            case.get("modifiedTimestamp") or case.get("modifiedTime") or created
        )
        severity = self._map_severity(
            case.get("consequenceSeverity", case.get("severity"))
        )
        description = (
            case.get("message")
            or case.get("description")
            or "Case imported from ArcSight ESM."
        )

        external_references = None
        if external_id:
            external_references = [
                {"source_name": "ArcSight ESM", "external_id": external_id}
            ]

        return CustomObjectCaseIncident(
            id=CaseIncident.generate_id(name, created),
            name=name,
            description=description,
            severity=severity,
            priority=_PRIORITY_MAPPING.get(severity, "P4"),
            created=created,
            modified=modified,
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking],
            external_references=external_references,
            object_refs=object_refs or [],
        )
