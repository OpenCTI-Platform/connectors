"""Converter from Swimlane records to STIX 2.1 objects."""

from datetime import datetime, timezone
from typing import Optional

import stix2
from pycti import CaseIncident, CustomObjectCaseIncident, Identity, MarkingDefinition

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

# Deterministic fallback for missing/invalid timestamps. CaseIncident.generate_id
# derives the STIX id from (name, created), so a datetime.now() fallback would
# mint a new id - and a duplicate Case-Incident - on every run for records that
# carry no usable timestamp. A fixed epoch anchor keeps the id stable.
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
    """Convert Swimlane record dictionaries into STIX 2.1 objects."""

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
            id=Identity.generate_id(name="Swimlane", identity_class="organization"),
            name="Swimlane",
            identity_class="organization",
            description="Records imported from Swimlane.",
        )

    @staticmethod
    def _to_iso(value) -> str:
        """
        Best-effort conversion of a Swimlane timestamp to a STIX-compatible UTC
        timestamp string (millisecond precision, ``Z`` suffix).
        """
        if value is None or value == "":
            dt = _FALLBACK_DT
        elif isinstance(value, (int, float)) or (
            isinstance(value, str) and value.isdigit()
        ):
            try:
                epoch = float(value)
                if epoch > 1e12:  # milliseconds
                    epoch /= 1000.0
                dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                # Out-of-range or non-finite epoch: fall back deterministically
                # instead of crashing the connector run.
                dt = _FALLBACK_DT
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

    def create_case_incident(self, record: dict) -> Optional[CustomObjectCaseIncident]:
        """
        Create a STIX Case-Incident from a Swimlane record dictionary.

        Swimlane is a case-management (SOAR) platform, so its records map to an
        OpenCTI Case-Incident (not an Incident, which is reserved for
        alerts/detections).
        """
        tracking = str(
            record.get("trackingId")
            or record.get("trackingFull")
            or record.get("id")
            or ""
        ).strip()
        name = f"Swimlane incident {tracking}" if tracking else "Swimlane incident"
        external_id = str(record.get("id") or tracking or "").strip()
        created = self._to_iso(record.get("createdDate") or record.get("created"))
        modified = self._to_iso(
            record.get("modifiedDate") or record.get("modified") or created
        )
        description = "Record imported from Swimlane."

        external_references = None
        if external_id:
            external_references = [
                {"source_name": "Swimlane", "external_id": external_id}
            ]

        return CustomObjectCaseIncident(
            id=CaseIncident.generate_id(name, created),
            name=name,
            description=description,
            created=created,
            modified=modified,
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking],
            external_references=external_references,
            object_refs=[],
        )
