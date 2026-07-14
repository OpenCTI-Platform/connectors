import ipaddress
from datetime import datetime
from typing import TYPE_CHECKING

import stix2
from pycti import (
    Identity,
    Indicator,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)

if TYPE_CHECKING:
    from external_import_connector import ConnectorSettings

# Map Flowtriq attack families to human-readable names
ATTACK_FAMILY_LABELS = {
    "syn_flood": "syn-flood",
    "udp_flood": "udp-flood",
    "dns_amplification": "dns-amplification",
    "ntp_amplification": "ntp-amplification",
    "ssdp_amplification": "ssdp-amplification",
    "memcached_amplification": "memcached-amplification",
    "icmp_flood": "icmp-flood",
    "tcp_flood": "tcp-flood",
    "http_flood": "http-flood",
    "gre_flood": "gre-flood",
    "chargen_amplification": "chargen-amplification",
    "cldap_amplification": "cldap-amplification",
    "ack_flood": "ack-flood",
    "rst_flood": "rst-flood",
    "mixed": "mixed-attack",
    "unknown": "unknown-attack",
}

SEVERITY_SCORE_MAP = {
    "critical": 95,
    "high": 80,
    "medium": 55,
    "low": 30,
}


class ConverterToStix:
    """
    Provides methods for converting Flowtriq DDoS incident data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper: "OpenCTIConnectorHelper", config: "ConnectorSettings"):
        self.helper = helper
        self.config = config
        self.author = self._create_author()
        self.external_reference = self._create_external_reference()
        self.tlp_marking = self._create_tlp_marking(
            self.config.flowtriq.tlp_level.lower()
        )

    @staticmethod
    def _create_external_reference() -> list[stix2.ExternalReference]:
        """
        Create external reference to the Flowtriq platform.
        """
        external_reference = stix2.ExternalReference(
            source_name="Flowtriq",
            url="https://flowtriq.com/",
            description="Flowtriq DDoS detection and network monitoring platform",
        )
        return [external_reference]

    @staticmethod
    def _create_author() -> stix2.Identity:
        """
        Create the Author identity for Flowtriq.
        """
        return stix2.Identity(
            id=Identity.generate_id(name="Flowtriq", identity_class="organization"),
            name="Flowtriq",
            identity_class="organization",
            description=(
                "Flowtriq is a network traffic monitoring and DDoS detection platform "
                "that provides real-time volumetric attack detection using NetFlow/sFlow analysis."
            ),
        )

    @staticmethod
    def _create_tlp_marking(level: str) -> stix2.MarkingDefinition:
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:CLEAR",
                },
            ),
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
        if level not in mapping:
            return mapping["clear"]
        return mapping[level]

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    def _severity_to_score(self, severity: str) -> int:
        """Map Flowtriq severity to an OpenCTI score (0-100)."""
        return SEVERITY_SCORE_MAP.get(severity, 50)

    def _format_volume(self, pps: int, bps: int) -> str:
        """Format peak PPS/BPS into a human-readable string."""
        parts = []
        if pps:
            if pps >= 1_000_000:
                parts.append(f"{pps / 1_000_000:.1f}Mpps")
            elif pps >= 1_000:
                parts.append(f"{pps / 1_000:.1f}Kpps")
            else:
                parts.append(f"{pps}pps")
        if bps:
            if bps >= 1_000_000_000:
                parts.append(f"{bps / 1_000_000_000:.1f}Gbps")
            elif bps >= 1_000_000:
                parts.append(f"{bps / 1_000_000:.1f}Mbps")
            elif bps >= 1_000:
                parts.append(f"{bps / 1_000:.1f}Kbps")
            else:
                parts.append(f"{bps}bps")
        return ", ".join(parts) if parts else "unknown volume"

    def create_incident_observable(
        self, incident: dict
    ) -> list[stix2.base._STIXBase]:
        """
        Convert a Flowtriq incident into STIX objects:
        - An IPv4Address or IPv6Address observable for the target IP
        - An Indicator with a STIX pattern (if create_indicator is enabled)
        - A Relationship linking the indicator to the observable

        Returns a list of STIX objects for this incident.
        """
        stix_objects: list[stix2.base._STIXBase] = []

        node = incident.get("node", {})
        target_ip = node.get("ip", "")
        node_name = node.get("name", "unknown")
        family = incident.get("family", "unknown")
        severity = incident.get("severity", "medium")
        peak_pps = incident.get("peak_pps", 0)
        peak_bps = incident.get("peak_bps", 0)
        started_at = incident.get("started_at")
        ended_at = incident.get("ended_at")
        incident_uuid = incident.get("uuid", "")

        if not target_ip:
            self.helper.connector_logger.warning(
                "[STIX] Incident has no target IP, skipping",
                {"uuid": incident_uuid},
            )
            return stix_objects

        if not (self._is_ipv4(target_ip) or self._is_ipv6(target_ip)):
            self.helper.connector_logger.error(
                "[STIX] Invalid target IP address",
                {"value": target_ip, "uuid": incident_uuid},
            )
            return stix_objects

        # Determine attack label
        attack_label = ATTACK_FAMILY_LABELS.get(family, family.replace("_", "-"))
        volume_str = self._format_volume(peak_pps, peak_bps)
        score = self._severity_to_score(severity)

        description = (
            f"DDoS attack target detected by Flowtriq. "
            f"Attack type: {attack_label}, severity: {severity}, "
            f"peak volume: {volume_str}. "
            f"Target: {target_ip} (node: {node_name})."
        )
        if started_at:
            description += f" Started: {started_at}."
        if ended_at:
            description += f" Ended: {ended_at}."

        # Build external references with incident-specific URL
        incident_refs = list(self.external_reference)
        if incident_uuid:
            incident_refs.append(
                stix2.ExternalReference(
                    source_name="Flowtriq Incident",
                    url=f"{self.config.flowtriq.api_url.rstrip('/')}/incidents/{incident_uuid}",
                    description=f"Flowtriq incident {incident_uuid}",
                )
            )

        labels = [f"ddos:{attack_label}", f"severity:{severity}"]

        custom_properties = {
            "x_opencti_created_by_ref": self.author["id"],
            "x_opencti_external_references": incident_refs,
            "x_opencti_description": description,
            "x_opencti_score": score,
            "x_opencti_labels": labels,
            "x_opencti_create_indicator": self.config.flowtriq.create_indicator,
        }

        # Create observable
        if self._is_ipv6(target_ip):
            observable = stix2.IPv6Address(
                value=target_ip,
                object_marking_refs=[self.tlp_marking],
                custom_properties=custom_properties,
            )
        else:
            observable = stix2.IPv4Address(
                value=target_ip,
                object_marking_refs=[self.tlp_marking],
                custom_properties=custom_properties,
            )
        stix_objects.append(observable)

        # Create indicator if configured
        if self.config.flowtriq.create_indicator:
            if self._is_ipv6(target_ip):
                pattern = f"[ipv6-addr:value = '{target_ip}']"
                obs_type = "IPv6-Addr"
            else:
                pattern = f"[ipv4-addr:value = '{target_ip}']"
                obs_type = "IPv4-Addr"

            # Parse valid_from from incident start time
            valid_from = datetime.utcnow()
            if started_at:
                try:
                    valid_from = datetime.fromisoformat(
                        started_at.replace("Z", "+00:00")
                    )
                except (ValueError, TypeError):
                    pass

            indicator = stix2.Indicator(
                id=Indicator.generate_id(pattern),
                name=f"DDoS target: {target_ip}",
                description=description,
                created_by_ref=self.author["id"],
                pattern_type="stix",
                pattern=pattern,
                valid_from=valid_from,
                external_references=incident_refs,
                object_marking_refs=[self.tlp_marking],
                labels=labels,
                custom_properties={
                    "x_opencti_score": score,
                    "x_opencti_main_observable_type": obs_type,
                },
            )
            stix_objects.append(indicator)

            # Create relationship: indicator "based-on" observable
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on", indicator.id, observable.id
                ),
                relationship_type="based-on",
                source_ref=indicator.id,
                target_ref=observable.id,
                created_by_ref=self.author["id"],
                object_marking_refs=[self.tlp_marking],
            )
            stix_objects.append(relationship)

        # Process source IPs from sp_top_sources if available
        top_sources = incident.get("sp_top_sources")
        if top_sources and isinstance(top_sources, list):
            for source in top_sources:
                source_ip = (
                    source.get("ip") if isinstance(source, dict) else str(source)
                )
                if not source_ip:
                    continue

                source_objects = self._create_source_ip_objects(
                    source_ip=source_ip,
                    target_observable=observable,
                    attack_label=attack_label,
                    severity=severity,
                    score=score,
                    incident_refs=incident_refs,
                    labels=labels,
                )
                stix_objects.extend(source_objects)

        return stix_objects

    def _create_source_ip_objects(
        self,
        source_ip: str,
        target_observable: stix2.IPv4Address | stix2.IPv6Address,
        attack_label: str,
        severity: str,
        score: int,
        incident_refs: list,
        labels: list[str],
    ) -> list[stix2.base._STIXBase]:
        """
        Create STIX objects for a DDoS source IP: observable, indicator, and relationships.
        """
        stix_objects: list[stix2.base._STIXBase] = []

        if not (self._is_ipv4(source_ip) or self._is_ipv6(source_ip)):
            return stix_objects

        source_desc = (
            f"DDoS attack source IP observed in {attack_label} attack "
            f"(severity: {severity}). Detected by Flowtriq."
        )

        source_custom = {
            "x_opencti_created_by_ref": self.author["id"],
            "x_opencti_external_references": incident_refs,
            "x_opencti_description": source_desc,
            "x_opencti_score": score,
            "x_opencti_labels": labels + ["ddos:source"],
            "x_opencti_create_indicator": self.config.flowtriq.create_indicator,
        }

        if self._is_ipv6(source_ip):
            source_obs = stix2.IPv6Address(
                value=source_ip,
                object_marking_refs=[self.tlp_marking],
                custom_properties=source_custom,
            )
        else:
            source_obs = stix2.IPv4Address(
                value=source_ip,
                object_marking_refs=[self.tlp_marking],
                custom_properties=source_custom,
            )
        stix_objects.append(source_obs)

        if self.config.flowtriq.create_indicator:
            if self._is_ipv6(source_ip):
                pattern = f"[ipv6-addr:value = '{source_ip}']"
                obs_type = "IPv6-Addr"
            else:
                pattern = f"[ipv4-addr:value = '{source_ip}']"
                obs_type = "IPv4-Addr"

            source_indicator = stix2.Indicator(
                id=Indicator.generate_id(pattern),
                name=f"DDoS source: {source_ip}",
                description=source_desc,
                created_by_ref=self.author["id"],
                pattern_type="stix",
                pattern=pattern,
                external_references=incident_refs,
                object_marking_refs=[self.tlp_marking],
                labels=labels + ["ddos:source"],
                custom_properties={
                    "x_opencti_score": score,
                    "x_opencti_main_observable_type": obs_type,
                },
            )
            stix_objects.append(source_indicator)

            # Indicator based-on observable
            rel_based = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on", source_indicator.id, source_obs.id
                ),
                relationship_type="based-on",
                source_ref=source_indicator.id,
                target_ref=source_obs.id,
                created_by_ref=self.author["id"],
                object_marking_refs=[self.tlp_marking],
            )
            stix_objects.append(rel_based)

        return stix_objects
