"""Converter from Corelight Investigator alerts/detections to STIX 2.1 objects."""

import ipaddress
from datetime import datetime, timezone
from typing import Optional

import stix2
from pycti import Identity, Incident, MarkingDefinition, StixCoreRelationship

# TLP levels that map directly to a stix2 built-in MarkingDefinition.
_TLP_MAPPING = {
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

# Fixed sentinel used when an alert provides no usable timestamp. Falling back to
# this constant (instead of "now") keeps the STIX created/modified - and the
# deterministic id - constant across runs, so a timestamp-less alert is not
# re-sent with drifting timestamps and needlessly updated every cycle.
_FALLBACK_TIMESTAMP = "1970-01-01T00:00:00.000Z"


def _statement_marking(definition: str) -> stix2.MarkingDefinition:
    """Build a custom statement MarkingDefinition for a TLP level.

    TLP:CLEAR and TLP:AMBER+STRICT are not stix2 built-ins. OpenCTI materializes them
    as statement markings whose canonical id is derived from the definition, so the UI
    shows the correct label instead of aliasing TLP:WHITE / TLP:AMBER (matches
    connectors-sdk ``TLPMarking.to_stix2_object``).
    """
    return stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("TLP", definition),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="TLP",
        x_opencti_definition=definition,
    )


def _resolve_tlp_marking(tlp_level: str) -> stix2.MarkingDefinition:
    if tlp_level == "clear":
        return _statement_marking("TLP:CLEAR")
    if tlp_level == "amber+strict":
        return _statement_marking("TLP:AMBER+STRICT")
    return _TLP_MAPPING.get(tlp_level, stix2.TLP_AMBER)


class ConverterToStix:
    """Convert Corelight Investigator alert dictionaries into STIX 2.1 objects."""

    def __init__(self, helper, tlp_level: str):
        self.helper = helper
        self.author = self._create_author()
        self.tlp_marking = _resolve_tlp_marking(tlp_level)

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
    def _parse_timestamp(value) -> Optional[datetime]:
        """Parse a Corelight timestamp into an aware UTC datetime.

        Returns ``None`` when the value is missing or cannot be parsed, so callers can
        tell a real source timestamp apart from a "now" fallback.
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
        source_dt = self._parse_timestamp(
            alert.get("timestamp")
            or alert.get("ts")
            or alert.get("start_time")
            or alert.get("created")
        )
        # Deterministic id: seed generate_id with the alert id (so distinct alerts
        # do not collide when their names repeat) plus the source timestamp. With no
        # usable timestamp the timestamp seed is None and created/modified fall back
        # to a fixed sentinel (never "now"), so a re-imported alert keeps a stable id
        # and is not re-sent with drifting timestamps each run.
        id_seed_name = f"{name} [{alert_id}]" if alert_id else name
        id_seed = self._format_iso(source_dt) if source_dt is not None else None
        created = (
            self._format_iso(source_dt)
            if source_dt is not None
            else _FALLBACK_TIMESTAMP
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
            id=Incident.generate_id(id_seed_name, id_seed),
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
