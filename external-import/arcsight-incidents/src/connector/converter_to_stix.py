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

# Fixed sentinel used when ArcSight provides no usable timestamp. Falling back to
# this constant (instead of "now") keeps the STIX created/modified - and the
# deterministic id - constant across runs, so a timestamp-less event/case is not
# re-sent with drifting timestamps and needlessly updated every cycle.
_FALLBACK_TIMESTAMP = "1970-01-01T00:00:00.000Z"


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
    def _parse_timestamp(value) -> Optional[datetime]:
        """
        Parse an ArcSight timestamp into an aware UTC datetime, or ``None`` when the
        value is missing or cannot be parsed, so callers can tell a real source
        timestamp apart from a "now" fallback.
        """
        if value is None or value == "":
            return None
        if isinstance(value, (int, float)) or (
            isinstance(value, str) and value.strip().isdigit()
        ):
            epoch = float(value)
            if epoch > 1e12:  # milliseconds
                epoch /= 1000.0
            return datetime.fromtimestamp(epoch, tz=timezone.utc)
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
        return (
            dt.replace(tzinfo=timezone.utc)
            if dt.tzinfo is None
            else dt.astimezone(timezone.utc)
        )

    @staticmethod
    def _format_iso(dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    @staticmethod
    def _to_iso(value) -> str:
        """
        Best-effort conversion of an ArcSight timestamp to a STIX-compatible UTC
        timestamp string (millisecond precision, ``Z`` suffix); falls back to "now"
        for missing or unparseable input.
        """
        return ConverterToStix._format_iso(
            ConverterToStix._parse_timestamp(value) or datetime.now(timezone.utc)
        )

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
        source_dt = self._parse_timestamp(
            event.get("endTime")
            or event.get("startTime")
            or event.get("managerReceiptTime")
        )
        # Deterministic id: seed generate_id with the event id (so distinct events
        # do not collide when their names repeat) plus the source timestamp. With
        # no usable timestamp the timestamp seed is None and created/modified fall
        # back to a fixed sentinel (never "now"), so a re-imported event keeps a
        # stable id and is not re-sent with drifting timestamps each run.
        id_seed_name = f"{name} [{event_id}]" if event_id else name
        id_seed = self._format_iso(source_dt) if source_dt is not None else None
        created = (
            self._format_iso(source_dt)
            if source_dt is not None
            else _FALLBACK_TIMESTAMP
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
            id=Incident.generate_id(id_seed_name, id_seed),
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
        source_dt = self._parse_timestamp(
            case.get("createdTimestamp") or case.get("createTime")
        )
        # See create_incident: seed the id with the case external id (so distinct
        # cases do not collide when names repeat) plus the source timestamp, and
        # fall back to a fixed sentinel - never "now" - when the case carries no
        # usable timestamp, so a re-imported case keeps a stable Case-Incident id
        # and is not re-sent with drifting created/modified each run.
        id_seed_name = f"{name} [{external_id}]" if external_id else name
        id_seed = self._format_iso(source_dt) if source_dt is not None else None
        created = (
            self._format_iso(source_dt)
            if source_dt is not None
            else _FALLBACK_TIMESTAMP
        )
        # Fall back to the already-stable created value (never "now") when the
        # modified timestamp is missing or unparseable, so the deterministic
        # Case-Incident id is not re-sent with a drifting modified each run.
        modified_dt = self._parse_timestamp(
            case.get("modifiedTimestamp") or case.get("modifiedTime")
        )
        modified = self._format_iso(modified_dt) if modified_dt is not None else created
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
            id=CaseIncident.generate_id(id_seed_name, id_seed),
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
