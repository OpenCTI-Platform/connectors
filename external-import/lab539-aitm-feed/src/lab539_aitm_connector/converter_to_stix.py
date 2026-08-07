"""STIX 2.1 conversion logic for the Lab539 AiTM Feed connector."""

import ipaddress
import uuid
from datetime import datetime, timezone

import stix2
from pycti import Identity, MarkingDefinition, OpenCTIConnectorHelper

CONFIDENCE_MAP = {
    "high": 90,
    "medium": 60,
    "low": 30,
}


class ConverterToStix:
    """Converts Lab539 AiTM Feed records to STIX 2.1 objects."""

    def __init__(self, helper: OpenCTIConnectorHelper, tlp_level: str = "amber"):
        self.helper = helper
        self.tlp_marking = self._resolve_tlp(tlp_level)
        self.author = self._create_author()

    def _resolve_tlp(self, tlp_level: str) -> stix2.MarkingDefinition:
        """Resolve a TLP level string to a STIX marking definition."""
        tlp_map = {
            "white": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            # TLP:AMBER+STRICT is not a built-in stix2 constant; build it as a
            # custom statement marking so the configured value is honored
            # instead of silently falling back to TLP:AMBER.
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
        return tlp_map.get(tlp_level.lower(), stix2.TLP_AMBER)

    def _create_author(self) -> stix2.Identity:
        """Create the Lab539 author identity object."""
        return stix2.Identity(
            id=Identity.generate_id("Lab539", "organization"),
            name="Lab539",
            identity_class="organization",
            description="Lab539 - AiTM threat intelligence provider",
            object_marking_refs=[self.tlp_marking],
        )

    def _get_ip_type(self, ip: str) -> str | None:
        """Return the STIX observable type for a given IP, or None if invalid."""
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return "ipv4-addr" if isinstance(parsed, ipaddress.IPv4Address) else "ipv6-addr"

    def _deterministic_id(self, stix_type: str, event_id: str, suffix: str = "") -> str:
        """Generate a deterministic STIX ID seeded from eventid."""
        seed = f"{stix_type}--{event_id}{suffix}"
        return f"{stix_type}--{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"

    def _build_indicator_description(self, record: dict) -> str:
        """Build a human-readable description for an indicator."""
        description = (
            f"AiTM infrastructure detected by Lab539. "
            f"ASN: {record.get('asn', '')}. "
            f"Country: {record.get('country', '')}. "
            f"Frontend: {record.get('frontend', False)}. "
            f"Backend: {record.get('backend', False)}. "
            f"Active at time of detection: {record.get('active', False)}."
        )
        if record.get("rdns"):
            description += f" rDNS: {record['rdns']}."
        return description

    def _build_pattern(self, ip: str, ip_type: str | None, domain_value: str) -> str:
        """
        Build a STIX pattern from the values that are actually present.

        Only valid IPs (with a resolved ip_type) and non-empty domains are
        included, so we never emit a clause for a missing/invalid value. Raises
        ValueError when there is nothing to build a pattern from.
        """
        pattern_parts = []
        if ip and ip_type:
            pattern_parts.append(f"[{ip_type}:value = '{ip}']")
        if domain_value:
            pattern_parts.append(f"[domain-name:value = '{domain_value}']")
        if not pattern_parts:
            raise ValueError(
                "record has neither a valid IP address nor a domain/hostname"
            )
        return " OR ".join(pattern_parts)

    def record_to_stix(self, record: dict) -> list:
        """Convert a single AiTM feed record to a list of STIX objects."""
        event_id = record.get("eventid", "")
        ip = record.get("ip", "")
        hostname = record.get("hostname", "")
        domain = record.get("domain", "")
        confidence = record.get("confidence", "medium")
        detected = record.get("detected", 0)
        timestamp = record.get("timestamp", 0)

        detected_dt = (
            datetime.fromtimestamp(detected, tz=timezone.utc)
            if detected
            else datetime.now(tz=timezone.utc)
        )
        timestamp_dt = (
            datetime.fromtimestamp(timestamp, tz=timezone.utc)
            if timestamp
            else datetime.now(tz=timezone.utc)
        )
        confidence_score = CONFIDENCE_MAP.get(confidence, 60)
        ip_type = self._get_ip_type(ip) if ip else None
        domain_value = domain if domain else hostname
        pattern = self._build_pattern(ip, ip_type, domain_value)
        description = self._build_indicator_description(record)

        if ip_type == "ipv4-addr":
            main_observable_type = "IPv4-Addr"
        elif ip_type == "ipv6-addr":
            main_observable_type = "IPv6-Addr"
        else:
            main_observable_type = "Domain-Name"

        indicator = stix2.Indicator(
            id=self._deterministic_id("indicator", event_id),
            name=f"AiTM Infrastructure - {hostname if hostname else ip}",
            description=description,
            pattern=pattern,
            pattern_type="stix",
            valid_from=detected_dt,
            confidence=confidence_score,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking],
            labels=["malicious-activity", "aitm", "phishing"],
            custom_properties={
                "x_opencti_score": confidence_score,
                "x_opencti_main_observable_type": main_observable_type,
                "x_opencti_create_observables": True,
                "x_lab539_eventid": event_id,
                "x_lab539_asn": record.get("asn", ""),
                "x_lab539_country": record.get("country", ""),
                "x_lab539_frontend": record.get("frontend", False),
                "x_lab539_backend": record.get("backend", False),
                "x_lab539_active": record.get("active", False),
                "x_lab539_rdns": record.get("rdns", ""),
                "x_lab539_timestamp": timestamp_dt.isoformat(),
                "x_lab539_detected": detected_dt.isoformat(),
            },
        )

        return [self.author, indicator]

    def records_to_bundle(self, records: list) -> stix2.Bundle:
        """Convert a list of AiTM feed records to a STIX bundle."""
        all_objects = []
        seen_ids = set()

        # Add author and TLP marking first
        for obj in [self.author, self.tlp_marking]:
            if obj.id not in seen_ids:
                all_objects.append(obj)
                seen_ids.add(obj.id)

        for record in records:
            try:
                stix_objects = self.record_to_stix(record)
            except ValueError as err:
                # Skip a malformed record rather than aborting the whole bundle,
                # so one bad record does not drop the entire import.
                self.helper.connector_logger.warning(
                    "Skipping record that cannot be converted to STIX",
                    meta={"eventid": record.get("eventid", ""), "error": str(err)},
                )
                continue
            for obj in stix_objects:
                if obj.id not in seen_ids:
                    all_objects.append(obj)
                    seen_ids.add(obj.id)

        return stix2.Bundle(objects=all_objects, allow_custom=True)
