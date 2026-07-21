"""Converter from LogRhythm cases to STIX 2.1 objects."""

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

# TLP:CLEAR and TLP:AMBER+STRICT are distinct OpenCTI markings (custom statement
# markings carrying x_opencti_definition), not aliases of the STIX markings, so
# they are built explicitly in _custom_tlp(). The plain STIX markings cover the
# rest.
_TLP_MAPPING = {
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red": stix2.TLP_RED,
}

# LogRhythm case priority is a 1-5 scale (5 = highest).
_PRIORITY_MAPPING = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "low"}

# OpenCTI case priority derived from the severity.
_CASE_PRIORITY_MAPPING = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}

# Deterministic fallback for missing/invalid timestamps. Incident.generate_id and
# CaseIncident.generate_id derive the STIX id from (name, created), so a
# datetime.now() fallback would mint a new id - and a duplicate object - on every
# run for records that carry no usable timestamp. A fixed epoch anchor keeps the
# id stable.
_FALLBACK_DT = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _custom_tlp(definition: str) -> stix2.MarkingDefinition:
    return stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("TLP", definition),
        definition_type="statement",
        definition={"statement": "custom"},
        custom_properties={
            "x_opencti_definition_type": "TLP",
            "x_opencti_definition": definition,
        },
    )


class ConverterToStix:
    """Convert LogRhythm case dictionaries into STIX 2.1 objects."""

    def __init__(self, helper, tlp_level: str):
        self.helper = helper
        self.author = self._create_author()
        if tlp_level == "amber+strict":
            self.tlp_marking = _custom_tlp("TLP:AMBER+STRICT")
        elif tlp_level == "clear":
            self.tlp_marking = _custom_tlp("TLP:CLEAR")
        else:
            self.tlp_marking = _TLP_MAPPING.get(tlp_level, stix2.TLP_AMBER)

    @staticmethod
    def _create_author() -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id(name="LogRhythm", identity_class="organization"),
            name="LogRhythm",
            identity_class="organization",
            description="Cases imported from LogRhythm.",
        )

    @staticmethod
    def _to_iso(value) -> str:
        """
        Best-effort conversion of a LogRhythm timestamp to a STIX-compatible UTC
        timestamp string (millisecond precision, ``Z`` suffix).
        """
        if value is None or value == "":
            dt = _FALLBACK_DT
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
                dt = _FALLBACK_DT
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
            return _PRIORITY_MAPPING.get(int(value), "low")
        return "low"

    @staticmethod
    def _map_risk(value) -> str:
        """Map a LogRhythm alarm risk score (0-100) to an OpenCTI severity."""
        try:
            score = int(value)
        except (TypeError, ValueError):
            return "low"
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        return "low"

    def create_incident(self, alarm: dict) -> Optional[stix2.Incident]:
        """
        Create a STIX Incident from a LogRhythm alarm.

        LogRhythm alarms are detections/alerts, so they map to an OpenCTI Incident
        (the case that groups them is modeled as a Case-Incident).
        """
        alarm_id = str(alarm.get("alarmId") or alarm.get("id") or "").strip()
        name = (
            alarm.get("alarmRuleName")
            or alarm.get("name")
            or (f"LogRhythm alarm {alarm_id}" if alarm_id else "LogRhythm alarm")
        )
        created = self._to_iso(
            alarm.get("alarmDate")
            or alarm.get("dateInserted")
            or alarm.get("dateCreated")
        )
        severity = self._map_risk(alarm.get("riskScore"))
        description = alarm.get("text") or "Alarm imported from LogRhythm."

        external_references = None
        if alarm_id:
            external_references = [
                {"source_name": "LogRhythm", "external_id": alarm_id}
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
                "source": "LogRhythm",
                "severity": severity,
                "incident_type": "alert",
            },
        )

    def create_case_incident(
        self, case: dict, object_refs=None
    ) -> Optional[CustomObjectCaseIncident]:
        """
        Create a STIX Case-Incident from a LogRhythm case dictionary.

        LogRhythm cases are case-management artifacts, so they map to an OpenCTI
        Case-Incident (not an Incident, which is reserved for alarms/detections).
        """
        number = str(case.get("number") or case.get("id") or "").strip()
        name = case.get("name") or (
            f"LogRhythm case {number}" if number else "LogRhythm case"
        )
        created = self._to_iso(case.get("dateCreated") or case.get("createdDate"))
        modified = self._to_iso(
            case.get("dateUpdated") or case.get("modifiedDate") or created
        )
        severity = self._map_severity(case.get("priority"))
        description = case.get("summary") or "Case imported from LogRhythm."

        external_references = None
        if number:
            external_references = [{"source_name": "LogRhythm", "external_id": number}]

        return CustomObjectCaseIncident(
            id=CaseIncident.generate_id(name, created),
            name=name,
            description=description,
            severity=severity,
            priority=_CASE_PRIORITY_MAPPING.get(severity, "P4"),
            created=created,
            modified=modified,
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking],
            external_references=external_references,
            object_refs=object_refs or [],
        )
