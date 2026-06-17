"""Converter from FortiSIEM incidents to STIX 2.1 objects."""

import ipaddress
from datetime import datetime, timezone
from typing import Optional

import stix2
from pycti import Identity, Incident, MarkingDefinition, StixCoreRelationship

_TLP_MAPPING = {
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red": stix2.TLP_RED,
}

# FortiSIEM exposes incident severity as a 0-10 number; map it to OpenCTI severity.
_SEVERITY_BANDS = [
    (9, "critical"),
    (7, "high"),
    (4, "medium"),
    (0, "low"),
]


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
    # TLP:CLEAR is a distinct OpenCTI marking (a custom statement marking with
    # x_opencti_definition="TLP:CLEAR"), not an alias of STIX TLP:WHITE. Using
    # TLP_WHITE here would surface TLP:WHITE in OpenCTI instead of TLP:CLEAR.
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
    """Convert FortiSIEM incident dictionaries into STIX 2.1 objects."""

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
            id=Identity.generate_id(name="FortiSIEM", identity_class="organization"),
            name="FortiSIEM",
            identity_class="organization",
            description="Incidents imported from FortiSIEM.",
        )

    @staticmethod
    def _to_iso(value) -> str:
        """
        Best-effort conversion of a FortiSIEM timestamp to a STIX-compatible
        UTC timestamp string (millisecond precision, ``Z`` suffix).
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

    def create_incident(self, incident: dict) -> Optional[stix2.Incident]:
        """Create a STIX Incident from a FortiSIEM incident dictionary."""
        name = (
            incident.get("incidentTitle")
            or incident.get("ruleName")
            or incident.get("name")
            or "FortiSIEM Incident"
        )
        external_id = str(
            incident.get("incidentId") or incident.get("id") or ""
        ).strip()
        source_created = incident.get("incidentFirstSeen") or incident.get(
            "firstSeenTime"
        )
        created = self._to_iso(source_created)
        modified = self._to_iso(
            incident.get("incidentLastSeen") or incident.get("lastSeenTime") or created
        )
        # Seed the Incident id with the source timestamp only. When the incident has
        # no first-seen timestamp, created falls back to "now"; passing None to
        # generate_id keeps the id stable across runs instead of creating a duplicate
        # Incident every import.
        id_seed = created if source_created else None
        severity = self._map_severity(
            incident.get("incidentSeverity", incident.get("severity"))
        )
        description = (
            incident.get("incidentDetail")
            or incident.get("description")
            or "Incident imported from FortiSIEM."
        )

        external_references = None
        if external_id:
            external_references = [
                {"source_name": "FortiSIEM", "external_id": external_id}
            ]

        return stix2.Incident(
            id=Incident.generate_id(name, id_seed),
            name=name,
            description=description,
            created=created,
            modified=modified,
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking],
            external_references=external_references,
            custom_properties={
                "source": "FortiSIEM",
                "severity": severity,
                "incident_type": "alert",
            },
        )

    def create_observable(self, value: str) -> Optional[object]:
        """Create a STIX observable (IPv4/IPv6/domain) from a value, or None."""
        if not value:
            return None
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            ip = None
        if isinstance(ip, ipaddress.IPv4Address):
            return stix2.IPv4Address(
                value=value,
                object_marking_refs=[self.tlp_marking],
                custom_properties={"x_opencti_created_by_ref": self.author["id"]},
            )
        if isinstance(ip, ipaddress.IPv6Address):
            return stix2.IPv6Address(
                value=value,
                object_marking_refs=[self.tlp_marking],
                custom_properties={"x_opencti_created_by_ref": self.author["id"]},
            )
        if "." in value and " " not in value:
            return stix2.DomainName(
                value=value,
                object_marking_refs=[self.tlp_marking],
                custom_properties={"x_opencti_created_by_ref": self.author["id"]},
            )
        return None

    def create_relationship(
        self, source_id: str, relationship_type: str, target_id: str
    ) -> stix2.Relationship:
        """Create a STIX relationship between two objects."""
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking],
        )
