"""STIX synchronizer for PortSpoofPro OpenCTI integration."""

import logging
import os
import uuid
from typing import Any, Dict, List, Optional

from constants import (
    AUTHOR_DESCRIPTION,
    AUTHOR_NAME,
    ENVIRONMENT,
    MAX_STRATEGIC_TARGET_RELATIONSHIPS,
    OPENCTI_NAMESPACE,
    OPENCTI_SSL_VERIFY_DEFAULT,
    SESSION_SOURCE_NAME,
    THREAT_ACTOR_SOURCE_NAME,
)
from helpers import (
    build_external_reference,
    build_session_external_references,
    calculate_opencti_score,
    generate_labels,
    map_threat_level,
    parse_iso_datetime,
    safe_get_float,
    safe_get_int,
)
from pycti import Identity as PyctiIdentity
from pycti import (
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    ThreatActorIndividual,
)
from stix2 import (
    TLP_WHITE,
    AttackPattern,
    Bundle,
    Identity,
    Indicator,
    IPv4Address,
    IPv6Address,
    NetworkTraffic,
    ObservedData,
    Relationship,
    Report,
    Sighting,
    ThreatActor,
    Tool,
)
from stix2.canonicalization.Canonicalize import canonicalize


def generate_deterministic_stix_id(object_type: str, properties: dict) -> str:
    """Generate deterministic STIX ID using uuid5 for automatic deduplication."""
    canonical_data = canonicalize(properties, utf8=False)
    deterministic_uuid = str(uuid.uuid5(OPENCTI_NAMESPACE, canonical_data))
    return f"{object_type}--{deterministic_uuid}"


def generate_tool_stix_id(tool_name: str) -> str:
    """Generate deterministic STIX ID for Tool objects."""
    from constants import PORTSPOOF_TOOL_NAMESPACE_PREFIX

    namespace_key = f"{PORTSPOOF_TOOL_NAMESPACE_PREFIX}-{tool_name.lower()}"
    deterministic_uuid = str(uuid.uuid5(OPENCTI_NAMESPACE, namespace_key))
    return f"tool--{deterministic_uuid}"


def generate_indicator_stix_id(source_ip: str) -> str:
    """Generate deterministic STIX ID for Indicator objects."""
    from constants import PORTSPOOF_INDICATOR_NAMESPACE_PREFIX

    namespace_key = f"{PORTSPOOF_INDICATOR_NAMESPACE_PREFIX}-{source_ip}"
    deterministic_uuid = str(uuid.uuid5(OPENCTI_NAMESPACE, namespace_key))
    return f"indicator--{deterministic_uuid}"


def generate_attack_pattern_stix_id(pattern_type: str, name: str) -> str:
    """Generate deterministic STIX ID for AttackPattern objects."""
    from constants import (
        PORTSPOOF_ATTACK_NAMESPACE_PREFIX,
        PORTSPOOF_BEHAVIOR_NAMESPACE_PREFIX,
        PORTSPOOF_MITRE_TTP_NAMESPACE_PREFIX,
        PORTSPOOF_TECHNIQUE_NAMESPACE_PREFIX,
    )

    if pattern_type == "technique":
        namespace_prefix = PORTSPOOF_TECHNIQUE_NAMESPACE_PREFIX
    elif pattern_type == "behavior":
        namespace_prefix = PORTSPOOF_BEHAVIOR_NAMESPACE_PREFIX
    elif pattern_type == "attack":
        namespace_prefix = PORTSPOOF_ATTACK_NAMESPACE_PREFIX
    elif pattern_type == "mitre":
        namespace_prefix = PORTSPOOF_MITRE_TTP_NAMESPACE_PREFIX
    else:
        logging.warning(
            f"Unknown pattern_type '{pattern_type}', using technique namespace"
        )
        namespace_prefix = PORTSPOOF_TECHNIQUE_NAMESPACE_PREFIX

    namespace_key = f"{namespace_prefix}-{name.lower()}"
    deterministic_uuid = str(uuid.uuid5(OPENCTI_NAMESPACE, namespace_key))
    return f"attack-pattern--{deterministic_uuid}"


def add_empty_where_sighted_refs(bundle_json: str) -> str:
    """Workaround for pycti bug - add empty where_sighted_refs to Sighting objects."""
    import json

    try:
        bundle_dict = json.loads(bundle_json)
        if "objects" in bundle_dict:
            for obj in bundle_dict["objects"]:
                if obj.get("type") == "sighting" and "where_sighted_refs" not in obj:
                    obj["where_sighted_refs"] = []
        return json.dumps(bundle_dict)
    except Exception as e:
        logging.warning(f"Failed to add where_sighted_refs workaround: {e}")
        return bundle_json


def build_config_from_env() -> Dict[str, Any]:
    """Build full OpenCTI Connector config from minimal environment variables."""
    opencti_url = os.getenv("OPENCTI_URL")
    opencti_token = os.getenv("OPENCTI_TOKEN")

    if not opencti_url or not opencti_token:
        raise ValueError(
            "Missing required environment variables: OPENCTI_URL and OPENCTI_TOKEN must be set"
        )

    connector_id = f"portspoof-pro-{uuid.uuid4()}"
    queue_protocol = os.getenv("CONNECTOR_QUEUE_PROTOCOL", "api")

    ssl_verify_env = os.getenv("OPENCTI_SSL_VERIFY", str(OPENCTI_SSL_VERIFY_DEFAULT))
    ssl_verify = ssl_verify_env.lower() in ("true", "1", "yes")

    return {
        "opencti": {
            "url": opencti_url,
            "token": opencti_token,
            "ssl_verify": ssl_verify,
        },
        "connector": {
            "id": connector_id,
            "type": "EXTERNAL_IMPORT",
            "name": "PortSpoofPro",
            "scope": "Threat-Actor,Observed-Data,IPv4-Addr,IPv6-Addr,Tool,Attack-Pattern,Infrastructure,Report,Relationship,Sighting",
            "confidence_level": 85,
            "log_level": "info",
            "queue_protocol": queue_protocol,
        },
        "portspoof": {
            "enable_auto_sync": True,
            "max_bundle_size": 1000,
            "max_target_ips": 10,
        },
    }


class IntelligenceExtractor:
    """Extracts threat intelligence from session state using pattern-based detection matching."""

    @staticmethod
    def extract(state: dict) -> dict:
        """Extract all intelligence from full state."""
        intelligence = {
            "detected_tools": [],
            "techniques": [],
            "behaviors": [],
            "attack_types": [],
            "scan_patterns": {},
            "evidence_attributes": {},
        }

        for detection in state.get("full_detection_chain", []):
            name = detection.get("name", "")
            attrs = detection.get("attributes", {})

            if name.startswith("fingerprint:"):
                tool_name = name.replace("fingerprint:", "")
                if tool_name not in intelligence["detected_tools"]:
                    intelligence["detected_tools"].append(tool_name)
            elif name.startswith("technique:"):
                technique_name = name.replace("technique:", "")
                if technique_name not in intelligence["techniques"]:
                    intelligence["techniques"].append(technique_name)
            elif name.startswith("behavior:"):
                behavior_name = name.replace("behavior:", "")
                if behavior_name not in intelligence["behaviors"]:
                    intelligence["behaviors"].append(behavior_name)
                if "recon" in behavior_name or "scan" in behavior_name:
                    intelligence["scan_patterns"][behavior_name] = True
            elif name.startswith("attack:"):
                attack_type = name.replace("attack:", "")
                if attack_type not in intelligence["attack_types"]:
                    intelligence["attack_types"].append(attack_type)

            for attr_name, attr_value in attrs.items():
                if isinstance(attr_value, (int, float)):
                    intelligence["evidence_attributes"][attr_name] = max(
                        intelligence["evidence_attributes"].get(attr_name, 0),
                        attr_value,
                    )
                else:
                    intelligence["evidence_attributes"][attr_name] = attr_value

        return intelligence


class DomainObjectManager:
    """Manages creation of Domain Objects (Tools, AttackPatterns) and their relationships."""

    @staticmethod
    def create_tool_objects(
        detected_tools: List[str],
        created_by_ref: str,
        marking_refs: List[str],
    ) -> List[Tool]:
        """Create Tool objects from detected tool names."""
        tools = []

        for tool_name in detected_tools:
            normalized_name = tool_name.lower().strip()
            if not normalized_name:
                continue

            tool_id = generate_tool_stix_id(normalized_name)
            display_name = normalized_name.capitalize()

            tool = Tool(
                id=tool_id,
                name=display_name,
                description=f"Scanning tool detected by PortSpoofPro: {display_name}",
                labels=["portspoof-pro", f"fingerprint:{normalized_name}"],
                created_by_ref=created_by_ref,
                object_marking_refs=marking_refs,
            )
            tools.append(tool)

        return tools

    @staticmethod
    def create_technique_attack_patterns(
        techniques: List[str],
        created_by_ref: str,
        marking_refs: List[str],
    ) -> List[AttackPattern]:
        """Create AttackPattern objects for scan techniques."""
        patterns = []

        for technique_name in techniques:
            normalized_name = technique_name.lower().strip()
            if not normalized_name:
                continue

            pattern_id = generate_attack_pattern_stix_id("technique", normalized_name)
            display_name = normalized_name.replace("_", " ").title()

            pattern = AttackPattern(
                id=pattern_id,
                name=display_name,
                description=f"Port scanning technique detected by PortSpoofPro: {display_name}",
                labels=["portspoof-pro", f"technique:{normalized_name}"],
                created_by_ref=created_by_ref,
                object_marking_refs=marking_refs,
            )
            patterns.append(pattern)

        return patterns

    @staticmethod
    def create_behavior_attack_patterns(
        behaviors: List[str],
        created_by_ref: str,
        marking_refs: List[str],
    ) -> List[AttackPattern]:
        """Create AttackPattern objects for behavioral patterns."""
        patterns = []

        for behavior_name in behaviors:
            normalized_name = behavior_name.lower().strip()
            if not normalized_name:
                continue

            pattern_id = generate_attack_pattern_stix_id("behavior", normalized_name)
            display_name = normalized_name.replace("_", " ").title()

            pattern = AttackPattern(
                id=pattern_id,
                name=display_name,
                description=f"Behavioral pattern detected by PortSpoofPro: {display_name}",
                labels=["portspoof-pro", f"behavior:{normalized_name}"],
                created_by_ref=created_by_ref,
                object_marking_refs=marking_refs,
            )
            patterns.append(pattern)

        return patterns

    @staticmethod
    def create_attack_attack_patterns(
        attack_types: List[str],
        created_by_ref: str,
        marking_refs: List[str],
    ) -> List[AttackPattern]:
        """Create AttackPattern objects for attack-level detections."""
        patterns = []

        for attack_name in attack_types:
            normalized_name = attack_name.lower().strip()
            if not normalized_name:
                continue

            pattern_id = generate_attack_pattern_stix_id("attack", normalized_name)
            display_name = normalized_name.replace("_", " ").title()

            pattern = AttackPattern(
                id=pattern_id,
                name=display_name,
                description=f"Attack pattern detected by PortSpoofPro: {display_name}",
                labels=["portspoof-pro", f"attack:{normalized_name}"],
                created_by_ref=created_by_ref,
                object_marking_refs=marking_refs,
            )
            patterns.append(pattern)

        return patterns

    @staticmethod
    def create_mitre_attack_patterns(
        mitre_ttp_ids: List[str],
        created_by_ref: str,
        marking_refs: List[str],
    ) -> List[AttackPattern]:
        """Create AttackPattern references for MITRE ATT&CK TTPs."""
        from constants import MITRE_ATTACK_SOURCE_NAME
        from helpers import format_mitre_ttp_name, format_mitre_ttp_url

        patterns = []

        for ttp_id in mitre_ttp_ids:
            normalized_ttp_id = ttp_id.upper().strip()
            if not normalized_ttp_id:
                continue

            display_name = format_mitre_ttp_name(normalized_ttp_id)
            ttp_url = format_mitre_ttp_url(normalized_ttp_id)
            pattern_id = generate_attack_pattern_stix_id("mitre", normalized_ttp_id)

            pattern = AttackPattern(
                id=pattern_id,
                name=display_name,
                description=f"MITRE ATT&CK technique {normalized_ttp_id} detected by PortSpoofPro",
                labels=["portspoof-pro", f"mitre-ttp:{normalized_ttp_id}"],
                external_references=[
                    {
                        "source_name": MITRE_ATTACK_SOURCE_NAME,
                        "external_id": normalized_ttp_id,
                        "url": ttp_url,
                    }
                ],
                created_by_ref=created_by_ref,
                object_marking_refs=marking_refs,
            )
            patterns.append(pattern)

        return patterns

    @staticmethod
    def create_threat_actor_relationships(
        threat_actor_id: str,
        tools: List[Tool],
        attack_patterns: List[AttackPattern],
        marking_refs: List[str],
    ) -> List[Relationship]:
        """Create 'uses' relationships between ThreatActorIndividual and Domain Objects."""
        relationships = []

        for tool in tools:
            rel_id = StixCoreRelationship.generate_id("uses", threat_actor_id, tool.id)
            rel = Relationship(
                id=rel_id,
                relationship_type="uses",
                source_ref=threat_actor_id,
                target_ref=tool.id,
                description=f"Threat actor uses {tool.name}",
                object_marking_refs=marking_refs,
            )
            relationships.append(rel)

        for pattern in attack_patterns:
            rel_id = StixCoreRelationship.generate_id(
                "uses", threat_actor_id, pattern.id
            )
            rel = Relationship(
                id=rel_id,
                relationship_type="uses",
                source_ref=threat_actor_id,
                target_ref=pattern.id,
                description=f"Threat actor employs {pattern.name}",
                object_marking_refs=marking_refs,
            )
            relationships.append(rel)

        return relationships


class IpObservableManager:
    """Manages IPv4/IPv6 Address observables."""

    @staticmethod
    def create_source_ip_observable(
        source_ip: str,
        session_id: str,
        state: dict,
        intelligence: dict,
        created_by_ref: str,
        marking_refs: List[str],
    ):
        """Create IPv4 or IPv6 Address observable for attacker IP with queryable labels."""
        from helpers import (
            calculate_duration_minutes,
            calculate_port_scan_metrics,
            calculate_port_volume_category,
            calculate_time_wasted_minutes,
            calculate_unique_tcp_ports,
        )

        risk_score = state.get("risk_score", 0)
        alert_level = state.get("alert_level", 0)
        total_ports_seen = state.get("total_ports_seen", 0)
        total_hosts_probed = state.get("total_hosts_probed", 0)
        time_wasted_secs = state.get("total_attacker_time_wasted_secs", 0)
        duration_secs = state.get("total_session_duration_secs", 0)
        probed_ports_detail = state.get("full_probed_ports") or {}

        time_wasted_mins = calculate_time_wasted_minutes(time_wasted_secs)
        duration_mins = calculate_duration_minutes(duration_secs)
        port_volume = calculate_port_volume_category(total_ports_seen)
        attacker_score = calculate_opencti_score(alert_level)

        port_scan_metrics = calculate_port_scan_metrics(probed_ports_detail)
        tcp_ports_total = calculate_unique_tcp_ports(probed_ports_detail)

        event_type = state.get("last_event_type", "")
        is_final_event = event_type == "scanner_session_ended"

        labels = [
            "portspoof-pro",
            "attacker-ip",
            "network-reconnaissance",
        ]

        labels.extend(
            [
                f"threat:{map_threat_level(alert_level).lower()}",
                f"port-volume:{port_volume}",
            ]
        )

        if is_final_event:
            labels.extend(
                [
                    f"risk-score:{int(risk_score)}",
                    f"ports-scanned:{total_ports_seen}",
                    f"hosts-probed:{total_hosts_probed}",
                    f"tcp-ports:{tcp_ports_total}",
                    f"udp-ports:{port_scan_metrics['udp_ports']}",
                ]
            )

            if time_wasted_mins > 0:
                labels.append(f"attacker-time-wasted-minutes:{time_wasted_mins}")
            if duration_mins > 0:
                labels.append(f"session-duration-minutes:{duration_mins}")

        tools = intelligence.get("detected_tools", [])
        techniques = intelligence.get("techniques", [])
        behaviors = intelligence.get("behaviors", [])
        attack_types = intelligence.get("attack_types", [])

        tools_str = ", ".join(tools) if tools else "None"
        techniques_str = ", ".join(techniques) if techniques else "None"
        behaviors_str = ", ".join(behaviors) if behaviors else "None"
        attacks_str = ", ".join(attack_types) if attack_types else "None"

        time_summary = (
            f"- Attacker time wasted: {time_wasted_mins} minutes (service emulation delays)\n"
            if time_wasted_mins > 0
            else ""
        )

        description = f"""Malicious IP observed by PortSpoofPro deception platform.

**Latest Session Metrics:**
- {total_hosts_probed} targets probed, {total_ports_seen} ports scanned
- TCP: {tcp_ports_total} ports, UDP: {port_scan_metrics['udp_ports']} ports
{time_summary}
**Latest Intelligence:**
- Tools: {tools_str}
- Techniques: {techniques_str}
- Behaviors: {behaviors_str}
- Attacks: {attacks_str}

**Current Threat Level:** {map_threat_level(alert_level)} (Risk Score: {int(risk_score)}/1000)

**For detailed breakdown:** See the related Observed-Data object for scan techniques, port lists, and evidence attributes.
**For complete forensics:** Query MongoDB session: `{session_id}`
**For TTP analysis:** See ThreatActor graph for complete attack patterns and relationships.
"""

        custom_properties = {
            "x_opencti_score": attacker_score,
            "x_opencti_description": description.strip(),
            "x_portspoof_tcp_ports": tcp_ports_total,
            "x_portspoof_udp_ports": port_scan_metrics["udp_ports"],
            "x_portspoof_risk_score": int(risk_score),
            "x_portspoof_ports_scanned": total_ports_seen,
            "x_portspoof_hosts_probed": total_hosts_probed,
            "x_portspoof_threat_level": map_threat_level(alert_level).lower(),
            "x_portspoof_port_volume_category": port_volume,
        }

        if time_wasted_mins > 0:
            custom_properties["x_portspoof_time_wasted_minutes"] = time_wasted_mins
        if duration_mins > 0:
            custom_properties["x_portspoof_duration_minutes"] = duration_mins

        if ":" in source_ip:
            return IPv6Address(
                value=source_ip,
                created_by_ref=created_by_ref,
                labels=labels,
                object_marking_refs=marking_refs,
                custom_properties=custom_properties,
                allow_custom=True,
            )
        else:
            return IPv4Address(
                value=source_ip,
                created_by_ref=created_by_ref,
                labels=labels,
                object_marking_refs=marking_refs,
                custom_properties=custom_properties,
                allow_custom=True,
            )

    @staticmethod
    def create_target_ip_observables(
        target_ips: List[str],
        max_targets: int,
        session_id: str,
        state: dict,
        created_by_ref: str,
        marking_refs: List[str],
    ):
        """Create IPv4/IPv6 Address observables for target hosts."""
        observables = []

        description = (
            "Target host scanned by attacker. See ObservedData for scan details."
        )

        labels = [
            "portspoof-pro",
            "victim",
            "target-host",
            f"session:{session_id[:8]}",
        ]

        custom_properties = {
            "x_opencti_description": description,
        }

        for ip in target_ips[:max_targets]:
            if ":" in ip:
                observables.append(
                    IPv6Address(
                        value=ip,
                        created_by_ref=created_by_ref,
                        labels=labels,
                        object_marking_refs=marking_refs,
                        custom_properties=custom_properties,
                        allow_custom=True,
                    )
                )
            else:
                observables.append(
                    IPv4Address(
                        value=ip,
                        created_by_ref=created_by_ref,
                        labels=labels,
                        object_marking_refs=marking_refs,
                        custom_properties=custom_properties,
                        allow_custom=True,
                    )
                )

        if len(target_ips) > max_targets:
            logging.debug(
                f"Limited target IPs from {len(target_ips)} to {max_targets} observables"
            )

        return observables

    @staticmethod
    def create_network_traffic_objects(
        source_ip_observable,
        target_ip_observables: List,
        session_id: str,
        state: dict,
        created_by_ref: str,
        marking_refs: List[str],
    ) -> List:
        """Create minimal Network-Traffic objects as relationship markers only."""
        network_traffic_objects = []
        total_targets = len(target_ip_observables)

        risk_score = state.get("risk_score", 0)
        network_traffic_score = min(100, int(risk_score / 10))

        for idx, target_ip_obs in enumerate(target_ip_observables, start=1):
            alias = f"{source_ip_observable.value} → {target_ip_obs.value}"

            description = (
                f"Network reconnaissance activity from {source_ip_observable.value} "
                f"targeting {target_ip_obs.value}. This host was one of {total_targets} "
                f"target(s) probed in this session. See ObservedData for complete scan "
                f"intelligence including port details and techniques."
            )

            # Generate deterministic ID for NetworkTraffic based on src/dst
            nt_id = generate_deterministic_stix_id(
                "network-traffic",
                {"src_ref": source_ip_observable.id, "dst_ref": target_ip_obs.id},
            )

            nt = NetworkTraffic(
                id=nt_id,
                src_ref=source_ip_observable.id,
                dst_ref=target_ip_obs.id,
                protocols=["tcp", "udp"],
                created_by_ref=created_by_ref,
                custom_properties={
                    "x_opencti_description": description,
                    "x_opencti_score": network_traffic_score,
                    "x_opencti_aliases": [alias],
                    "x_opencti_additional_names": [alias],
                    "labels": [
                        "portspoof-pro",
                        "network-reconnaissance",
                        f"target:{idx}",
                        f"session:{session_id[:8]}",
                    ],
                },
                object_marking_refs=marking_refs,
                allow_custom=True,
            )
            network_traffic_objects.append(nt)

        logging.info(
            f"Created {len(network_traffic_objects)} Network-Traffic objects "
            f"(relationship markers only - port data in ObservedData)"
        )
        return network_traffic_objects


class ObservedDataManager:
    """Manages Observed-Data objects with telemetry in custom properties."""

    @staticmethod
    def create_observed_data(
        state: dict,
        intelligence: dict,
        source_ip_observable,
        target_ip_observables: List,
        network_traffic_objects: List,
        created_by_ref: str,
        marking_refs: List[str],
        session_id: str,
        capping_label: Optional[str] = None,
    ):
        """Create Observed-Data with queryable labels and evidence custom properties."""
        from helpers import (
            calculate_duration_minutes,
            calculate_port_scan_metrics,
            calculate_port_volume_category,
            calculate_time_wasted_minutes,
            calculate_unique_tcp_ports,
        )

        try:
            object_refs = [source_ip_observable.id]
            for target_ip in target_ip_observables:
                object_refs.append(target_ip.id)
            for nt in network_traffic_objects:
                object_refs.append(nt.id)

            risk_score = state.get("risk_score", 0)
            alert_level = state.get("alert_level", 0)
            total_ports_seen = state.get("total_ports_seen", 0)
            total_hosts_probed = state.get("total_hosts_probed", 0)
            time_wasted_secs = state.get("total_attacker_time_wasted_secs", 0)
            duration_secs = state.get("total_session_duration_secs", 0)
            sensor_id = state.get("sensor_id") or "none"
            sensor_hostname = state.get("sensor_hostname") or "none"

            probed_ports_detail = state.get("full_probed_ports") or {}

            time_wasted_mins = calculate_time_wasted_minutes(time_wasted_secs)
            duration_mins = calculate_duration_minutes(duration_secs)
            port_volume = calculate_port_volume_category(total_ports_seen)
            normalized_score = min(100, int(risk_score / 10))

            port_scan_metrics = calculate_port_scan_metrics(probed_ports_detail)
            tcp_ports_total = calculate_unique_tcp_ports(probed_ports_detail)

            session_label = f"session:{sensor_id}:{session_id}"

            labels = [
                "portspoof-pro",
                "scan-intelligence",
                session_label,
                f"threat:{map_threat_level(alert_level).lower()}",
                f"risk-score:{int(risk_score)}",
                f"ports-scanned:{total_ports_seen}",
                f"hosts-probed:{total_hosts_probed}",
                f"port-volume:{port_volume}",
                f"tcp-ports:{tcp_ports_total}",
                f"udp-ports:{port_scan_metrics['udp_ports']}",
                f"syn-ports:{port_scan_metrics['syn_ports']}",
                f"fin-ports:{port_scan_metrics['fin_ports']}",
                f"ack-ports:{port_scan_metrics['ack_ports']}",
            ]

            if time_wasted_mins > 0:
                labels.append(f"attacker-time-wasted-minutes:{time_wasted_mins}")
            if duration_mins > 0:
                labels.append(f"session-duration-minutes:{duration_mins}")

            labels.append(f"sensor:{sensor_id}")
            labels.append(f"sensor-host:{sensor_hostname}")

            if capping_label:
                labels.append(capping_label)
            description = ObservedDataManager._build_description_summary(
                state, intelligence, time_wasted_mins, duration_mins
            )

            custom_properties = {
                "x_opencti_description": description,
                "x_opencti_score": normalized_score,
            }

            evidence_attributes = intelligence.get("evidence_attributes", {})

            evidence_mapping = {
                "peak_concurrent": "x_portspoof_evidence_peak_concurrent",
                "velocity": "x_portspoof_evidence_velocity",
                "connection_count": "x_portspoof_evidence_connection_count",
                "syn_probe_count": "x_portspoof_evidence_syn_probe_count",
                "udp_packets_received": "x_portspoof_evidence_udp_packets_received",
                "udp_unique_ports_probed": "x_portspoof_evidence_udp_unique_ports_probed",
                "session_duration": "x_portspoof_evidence_session_duration",
                "bytes_sent": "x_portspoof_evidence_bytes_sent",
                "interaction_count": "x_portspoof_evidence_interaction_count",
                "destination_host_count": "x_portspoof_evidence_destination_host_count",
                "port_count": "x_portspoof_evidence_port_count",
            }

            for source_key, target_key in evidence_mapping.items():
                if source_key in evidence_attributes:
                    value = evidence_attributes[source_key]
                    if isinstance(value, (int, float)):
                        custom_properties[target_key] = value

            # Generate deterministic ID for ObservedData based on session
            observed_data_id = generate_deterministic_stix_id(
                "observed-data", {"session_id": session_id, "sensor_id": sensor_id}
            )

            observed_data = ObservedData(
                id=observed_data_id,
                first_observed=parse_iso_datetime(state.get("session_start_time")),
                last_observed=parse_iso_datetime(state.get("last_activity_time")),
                number_observed=1,
                object_refs=object_refs,
                created_by_ref=created_by_ref,
                object_marking_refs=marking_refs,
                labels=labels,
                external_references=[
                    {"source_name": SESSION_SOURCE_NAME, "external_id": session_id}
                ],
                custom_properties=custom_properties,
                allow_custom=True,
            )

            evidence_props_count = len(custom_properties) - 2

            logging.debug(
                f"Created Observed-Data: {observed_data.id} with {len(object_refs)} object_refs, "
                f"{len(labels)} queryable labels, {evidence_props_count} evidence properties"
            )
            return observed_data

        except Exception as e:
            logging.error(f"Failed to create Observed-Data: {e}")
            return None

    @staticmethod
    def _build_description_summary(
        state: dict, intelligence: dict, time_wasted_mins: int, duration_mins: int
    ) -> str:
        """Build human-readable summary description for ObservedData."""
        from helpers import format_port_list_by_technique

        session_id = state["session_id"]
        source_ip = state.get("source_ip", "unknown")
        risk_score = state.get("risk_score", 0)
        alert_level = state.get("alert_level", 0)
        total_ports_seen = state.get("total_ports_seen", 0)
        total_hosts_probed = state.get("total_hosts_probed", 0)
        sensor_hostname = state.get("sensor_hostname") or "none"
        probed_ports_detail = state.get("full_probed_ports") or {}
        target_hosts = state.get("full_probed_hosts") or []

        tools = intelligence.get("detected_tools", [])
        techniques = intelligence.get("techniques", [])
        behaviors = intelligence.get("behaviors", [])
        attack_types = intelligence.get("attack_types", [])

        tools_str = ", ".join(tools) if tools else "None"
        techniques_str = ", ".join(techniques) if techniques else "None"
        behaviors_str = ", ".join(behaviors) if behaviors else "None"
        attacks_str = ", ".join(attack_types) if attack_types else "None"

        target_list = "\n".join(
            f"  {idx+1}. {ip}" for idx, ip in enumerate(target_hosts[:10])
        )
        if len(target_hosts) > 10:
            target_list += f"\n  ... and {len(target_hosts) - 10} more"

        time_wasted_line = (
            f"**Time Wasted:** {time_wasted_mins} minutes (service emulation delays)\n"
            if time_wasted_mins > 0
            else ""
        )
        duration_line = (
            f"**Duration:** {duration_mins} minutes\n" if duration_mins > 0 else ""
        )

        port_list_str = format_port_list_by_technique(
            probed_ports_detail, max_ports_per_technique=10
        )
        port_section = ""
        if port_list_str:
            port_section = f"""
## Port Scanning Details
{port_list_str}

"""

        description = f"""# Scan Intelligence Report

**Session ID:** {session_id}
**Source IP:** {source_ip}
**Risk Score:** {risk_score:.0f} / 1000 (Alert Level: {alert_level})
{time_wasted_line}{duration_line}**Sensor:** {sensor_hostname}

## Reconnaissance Summary
- **Targets Probed:** {total_hosts_probed} unique hosts
- **Total Ports Scanned:** {total_ports_seen} unique ports (cumulative across all targets)
- **Scan Techniques:** {len(probed_ports_detail)} methods detected
{port_section}
## Intelligence
- **Detected Tools:** {tools_str}
- **Scan Techniques:** {techniques_str}
- **Behavioral Patterns:** {behaviors_str}
- **Attack Patterns:** {attacks_str}

## Target Infrastructure
{target_list}

**Full port list:** Query MongoDB: `db.sessions.findOne({{"session_id": "{session_id}"}}, {{"full_probed_ports": 1}})`
**Note:** Port data is cumulative across all targets. Individual per-target port mappings are not available in PortSpoofPro's aggregator output.
"""
        return description.strip()

    @staticmethod
    def _map_threat_level(alert_level: int) -> str:
        """Map alert level to threat level string."""
        mapping = {0: "Info", 1: "Suspicious", 2: "High", 3: "Critical"}
        return mapping.get(alert_level, "Unknown")


class StixSynchronizer:
    """OpenCTI synchronizer for PortSpoofPro threat intelligence."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize synchronizer with OpenCTI Connector Framework."""
        self.helper = OpenCTIConnectorHelper(config)
        self.api = self.helper.api

        logging.info(f"Initialized PortSpoofPro connector: {self.helper.connect_id}")
        logging.info(f"Connector name: {self.helper.connect_name}")
        logging.info(f"Connector type: {self.helper.connect_type}")

        try:
            identity_dict = self.api.identity.create(
                type="Organization", name=AUTHOR_NAME, description=AUTHOR_DESCRIPTION
            )
            self.author_opencti_id = identity_dict["id"]
            self.author_standard_id = (
                identity_dict.get("standard_id") or identity_dict["id"]
            )
            logging.info(
                f"Author identity: OpenCTI ID={self.author_opencti_id}, STIX ID={self.author_standard_id}"
            )
        except Exception as e:
            logging.error(f"FATAL: Failed to create author identity: {e}")
            raise

        try:
            markings = self.api.marking_definition.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "definition", "values": ["TLP:CLEAR"]}],
                    "filterGroups": [],
                }
            )
            if markings and len(markings) > 0:
                tlp_clear = markings[0]
                self.tlp_clear_opencti_id = tlp_clear["id"]
                self.tlp_clear_stix_id = tlp_clear.get("standard_id") or tlp_clear["id"]
                logging.info(
                    f"Using existing TLP:CLEAR marking: STIX ID={self.tlp_clear_stix_id}"
                )
            else:
                self.tlp_clear_stix_id = (
                    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                )
                self.tlp_clear_opencti_id = self.api.marking_definition.read(
                    id=self.tlp_clear_stix_id
                )["id"]
                logging.info(f"Using standard TLP:CLEAR ID: {self.tlp_clear_stix_id}")
        except Exception as e:
            logging.warning(
                f"Failed to query TLP:CLEAR marking: {e}. Using standard ID."
            )
            self.tlp_clear_stix_id = (
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            )
            self.tlp_clear_opencti_id = self.tlp_clear_stix_id

        self.extractor = IntelligenceExtractor()
        self._seen_threat_actor_ips = set()

        self.stats = {
            "sessions_synced": 0,
            "threat_actors_created": 0,
            "threat_actors_updated": 0,
            "infrastructures_created": 0,
            "observed_data_created": 0,
            "tools_created": 0,
            "attack_patterns_created": 0,
            "indicators_created": 0,
            "sightings_created": 0,
            "reports_created": 0,
            "relationships_created": 0,
            "api_errors": 0,
        }

    def log_statistics(self):
        """Log current synchronizer statistics."""
        logging.info("=" * 60)
        logging.info("STIX Synchronizer Statistics:")
        logging.info(f"  Sessions synced: {self.stats['sessions_synced']}")
        logging.info(
            f"  Threat Actors created: {self.stats['threat_actors_created']:,}"
        )
        logging.info(
            f"  Threat Actors updated: {self.stats['threat_actors_updated']:,}"
        )
        logging.info(f"  Observed data created: {self.stats['observed_data_created']}")
        logging.info(f"  Tools created: {self.stats['tools_created']}")
        logging.info(
            f"  Attack Patterns created: {self.stats['attack_patterns_created']}"
        )
        logging.info(f"  Indicators created: {self.stats['indicators_created']}")
        logging.info(f"  Sightings created: {self.stats['sightings_created']}")
        logging.info(f"  Reports created: {self.stats['reports_created']}")
        logging.info(f"  Relationships created: {self.stats['relationships_created']}")
        logging.info(f"  API errors: {self.stats['api_errors']}")
        logging.info("=" * 60)

    def sync_session(self, state: dict):
        """Synchronize session state to OpenCTI using STIX2 Bundle."""
        session_id = state["session_id"]
        source_ip = state["source_ip"]
        event_type = state.get("last_event_type", "unknown")

        logging.info(
            f"Syncing session {session_id} from {source_ip} (event: {event_type})"
        )

        work_id = self._initiate_work(session_id, source_ip)
        bundle_objects = []

        try:
            intelligence = self.extractor.extract(state)
            logging.debug(
                f"Extracted intelligence: {len(intelligence['detected_tools'])} tools, "
                f"{len(intelligence['techniques'])} techniques"
            )

            threat_actor = self._create_threat_actor(state, intelligence, session_id)
            bundle_objects.append(threat_actor)
            self._track_threat_actor_stats(source_ip)

            ip_objects = self._create_ip_observables_and_relationships(
                state, intelligence, threat_actor, session_id
            )
            bundle_objects.append(ip_objects["source_ip_observable"])
            bundle_objects.extend(ip_objects["target_ip_observables"])
            bundle_objects.extend(ip_objects.get("victim_observables_for_rels", []))
            bundle_objects.extend(ip_objects["network_traffic_objects"])
            bundle_objects.extend(ip_objects["relationships"])

            indicator_objects = self._create_indicators_and_relationships(
                state,
                intelligence,
                threat_actor,
                ip_objects["source_ip_observable"],
                session_id,
            )
            bundle_objects.extend(indicator_objects)

            indicator = indicator_objects[0] if indicator_objects else None
            self._create_observed_data_and_sighting(
                state,
                intelligence,
                ip_objects["source_ip_observable"],
                ip_objects["target_ip_observables"],
                ip_objects["network_traffic_objects"],
                threat_actor,
                indicator,
                session_id,
                bundle_objects,
                capping_label=ip_objects.get("capping_label"),
            )

            tools_and_patterns = self._create_tools_and_attack_patterns(
                state, intelligence, threat_actor, session_id
            )
            bundle_objects.extend(tools_and_patterns)

            if state.get("last_event_type") == "scanner_session_ended":
                report = self._create_session_report(
                    state, intelligence, bundle_objects, session_id
                )
                if report:
                    bundle_objects.append(report)

            self._send_bundle(bundle_objects, work_id, session_id)
            self._complete_work(work_id, session_id, source_ip, len(bundle_objects))
            self.stats["sessions_synced"] += 1

        except Exception as e:
            self._handle_sync_error(work_id, session_id, e)
            raise

    def _initiate_work(self, session_id: str, source_ip: str) -> str:
        """Initiate work tracking in OpenCTI."""
        friendly_name = f"PortSpoofPro Session {session_id} ({source_ip})"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        logging.info(f"Initiated work: {work_id}")
        return work_id

    def _create_threat_actor(
        self, state: dict, intelligence: dict, session_id: str
    ) -> ThreatActor:
        """Create Threat-Actor STIX object as Individual."""
        source_ip = state["source_ip"]
        event_type = state.get("last_event_type", "")

        labels = generate_labels(state, intelligence, event_type)

        threat_actor_id = ThreatActorIndividual.generate_id(name=source_ip)

        sensor_id = state.get("sensor_id") or "none"
        session_id_with_sensor = f"{sensor_id}:{session_id}"

        custom_properties = {
            "x_portspoof_session_id": session_id_with_sensor,
            "x_portspoof_risk_score": int(state.get("risk_score", 0)),
            "x_portspoof_alert_level": state.get("alert_level", 0),
            "x_portspoof_threat_level": map_threat_level(
                state.get("alert_level", 0)
            ).lower(),
        }

        return ThreatActor(
            id=threat_actor_id,
            name=source_ip,
            threat_actor_types=["hacker"],
            resource_level="individual",
            created_by_ref=self.author_standard_id,
            object_marking_refs=[self.tlp_clear_stix_id],
            labels=labels,
            description=f"Individual threat actor observed by PortSpoofPro deception platform, identified by source IP {source_ip}.",
            external_references=build_session_external_references(
                session_id,
                additional_refs=[
                    build_external_reference(THREAT_ACTOR_SOURCE_NAME, source_ip)
                ],
            ),
            custom_properties=custom_properties,
            allow_custom=True,
        )

    def _track_threat_actor_stats(self, source_ip: str):
        """Track whether this is a new or updated Threat-Actor."""
        if source_ip in self._seen_threat_actor_ips:
            self.stats["threat_actors_updated"] += 1
            logging.debug(f"Updating existing Threat-Actor for {source_ip}")
        else:
            self.stats["threat_actors_created"] += 1
            self._seen_threat_actor_ips.add(source_ip)
            logging.debug(f"Creating new Threat-Actor for {source_ip}")

    def _create_ip_observables_and_relationships(
        self,
        state: dict,
        intelligence: dict,
        threat_actor: ThreatActor,
        session_id: str,
    ) -> dict:
        """Create IP observables and strategic target relationships."""
        source_ip = state["source_ip"]

        source_ip_observable = IpObservableManager.create_source_ip_observable(
            source_ip=source_ip,
            session_id=session_id,
            state=state,
            intelligence=intelligence,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
        )

        target_hosts = state.get("full_probed_hosts", [])
        total_victims = len(target_hosts)
        event_type = state.get("last_event_type", "")
        create_targets_relationships = event_type == "scanner_session_ended"

        if create_targets_relationships:
            sorted_victims = sorted(target_hosts)
            capped_victims = sorted_victims[:MAX_STRATEGIC_TARGET_RELATIONSHIPS]

            is_capped = total_victims > MAX_STRATEGIC_TARGET_RELATIONSHIPS
            capping_label = (
                f"targets-capped-at:{MAX_STRATEGIC_TARGET_RELATIONSHIPS}"
                if is_capped
                else None
            )

            logging.info(
                f"Final session event: Creating targets relationships for {len(capped_victims)} victims "
                f"(total: {total_victims}, capped: {is_capped})"
            )

            target_ip_observables = IpObservableManager.create_target_ip_observables(
                target_ips=capped_victims[:3],
                max_targets=3,
                session_id=session_id,
                state=state,
                created_by_ref=self.author_standard_id,
                marking_refs=[self.tlp_clear_stix_id],
            )
        else:
            capped_victims = []
            capping_label = None

            target_ip_observables = IpObservableManager.create_target_ip_observables(
                target_ips=target_hosts[:3],
                max_targets=3,
                session_id=session_id,
                state=state,
                created_by_ref=self.author_standard_id,
                marking_refs=[self.tlp_clear_stix_id],
            )

            logging.info(
                f"Incremental update ({event_type}): Skipping targets relationships"
            )

        network_traffic_objects = IpObservableManager.create_network_traffic_objects(
            source_ip_observable=source_ip_observable,
            target_ip_observables=target_ip_observables,
            session_id=session_id,
            state=state,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
        )

        source_ip_rel_id = StixCoreRelationship.generate_id(
            "related-to", threat_actor.id, source_ip_observable.id
        )
        source_ip_relationship = Relationship(
            id=source_ip_rel_id,
            relationship_type="related-to",
            source_ref=threat_actor.id,
            target_ref=source_ip_observable.id,
            created_by_ref=self.author_standard_id,
            object_marking_refs=[self.tlp_clear_stix_id],
            description=f"Threat actor identified by source IP address {source_ip}.",
            external_references=[
                {"source_name": SESSION_SOURCE_NAME, "external_id": session_id}
            ],
        )
        self.stats["relationships_created"] += 1

        targets_relationships = []
        victim_observables_for_rels = []

        if create_targets_relationships:
            session_start = parse_iso_datetime(state.get("session_start_time"))
            session_end = parse_iso_datetime(state.get("last_activity_time"))

            for victim_ip in capped_victims:
                if ":" in victim_ip:
                    victim_observable = IPv6Address(
                        value=victim_ip,
                        created_by_ref=self.author_standard_id,
                        labels=["portspoof-pro", "victim", "target-host"],
                        object_marking_refs=[self.tlp_clear_stix_id],
                        custom_properties={
                            "x_opencti_description": "Target host scanned by attacker."
                        },
                        allow_custom=True,
                    )
                else:
                    victim_observable = IPv4Address(
                        value=victim_ip,
                        created_by_ref=self.author_standard_id,
                        labels=["portspoof-pro", "victim", "target-host"],
                        object_marking_refs=[self.tlp_clear_stix_id],
                        custom_properties={
                            "x_opencti_description": "Target host scanned by attacker."
                        },
                        allow_custom=True,
                    )
                victim_observables_for_rels.append(victim_observable)

                # Generate deterministic ID using pycti helper
                rel_id = StixCoreRelationship.generate_id(
                    "targets",
                    threat_actor.id,
                    victim_observable.id,
                    session_start,
                    session_end,
                )

                target_relationship = Relationship(
                    id=rel_id,
                    relationship_type="targets",
                    source_ref=threat_actor.id,
                    target_ref=victim_observable.id,
                    description=f"Targeted victim {victim_ip} during reconnaissance session.",
                    start_time=session_start,
                    stop_time=session_end,
                    created_by_ref=self.author_standard_id,
                    object_marking_refs=[self.tlp_clear_stix_id],
                    external_references=[
                        {"source_name": SESSION_SOURCE_NAME, "external_id": session_id}
                    ],
                    allow_custom=True,
                )
                targets_relationships.append(target_relationship)
                self.stats["relationships_created"] += 1

            logging.info(
                f"Created {len(victim_observables_for_rels)} victim IP observables, "
                f"{len(targets_relationships)} 'targets' relationships "
                f"(capped: {is_capped}, total victims: {total_victims})"
            )

        return {
            "source_ip_observable": source_ip_observable,
            "target_ip_observables": target_ip_observables,
            "victim_observables_for_rels": victim_observables_for_rels,
            "network_traffic_objects": network_traffic_objects,
            "relationships": [source_ip_relationship] + targets_relationships,
            "capping_label": capping_label,
        }

    def _create_indicators_and_relationships(
        self,
        state: dict,
        intelligence: dict,
        threat_actor: ThreatActor,
        source_ip_observable,
        session_id: str,
    ) -> List:
        """Create Indicator objects with based-on and indicates relationships."""
        objects = []
        source_ip = state["source_ip"]
        risk_score = state.get("risk_score", 0)
        alert_level = state.get("alert_level", 0)
        labels = generate_labels(state, intelligence, state.get("last_event_type"))

        indicator_pattern = f"[ipv4-addr:value = '{source_ip}']"
        if ":" in source_ip:
            indicator_pattern = f"[ipv6-addr:value = '{source_ip}']"

        indicator_name = f"Malicious IP: {source_ip}"
        indicator_description = f"""Port scanning activity detected by PortSpoofPro deception sensor.

**Risk Score:** {risk_score}/100
**Alert Level:** {alert_level} ({map_threat_level(alert_level)})
**Total Ports Probed:** {state.get('total_ports_seen', 0)}
**Total Hosts Targeted:** {state.get('total_hosts_probed', 0)}
**Session ID:** {session_id}

This indicator represents confirmed malicious activity observed through direct interaction with deception infrastructure.""".strip()

        indicator = Indicator(
            id=generate_indicator_stix_id(source_ip),
            pattern=indicator_pattern,
            pattern_type="stix",
            name=indicator_name,
            description=indicator_description,
            valid_from=parse_iso_datetime(state["session_start_time"]),
            labels=labels,
            confidence=85,
            created_by_ref=self.author_standard_id,
            object_marking_refs=[self.tlp_clear_stix_id],
            external_references=build_session_external_references(session_id),
            custom_properties={
                "x_opencti_score": calculate_opencti_score(alert_level),
                "x_opencti_main_observable_type": (
                    "IPv6-Addr" if ":" in source_ip else "IPv4-Addr"
                ),
                "x_portspoof_risk_score": float(risk_score),
                "x_portspoof_session_id": session_id,
                "x_portspoof_alert_level": alert_level,
            },
        )
        objects.append(indicator)
        self.stats["indicators_created"] += 1

        based_on_rel_id = StixCoreRelationship.generate_id(
            "based-on", indicator.id, source_ip_observable.id
        )
        based_on_rel = Relationship(
            id=based_on_rel_id,
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=source_ip_observable.id,
            created_by_ref=self.author_standard_id,
            object_marking_refs=[self.tlp_clear_stix_id],
            description=f"Indicator is based on observable {source_ip}.",
            external_references=[
                {"source_name": SESSION_SOURCE_NAME, "external_id": session_id}
            ],
        )
        objects.append(based_on_rel)
        self.stats["relationships_created"] += 1

        indicates_rel_id = StixCoreRelationship.generate_id(
            "indicates", indicator.id, threat_actor.id
        )
        indicates_rel = Relationship(
            id=indicates_rel_id,
            relationship_type="indicates",
            source_ref=indicator.id,
            target_ref=threat_actor.id,
            created_by_ref=self.author_standard_id,
            object_marking_refs=[self.tlp_clear_stix_id],
            description=f"Indicator of compromise representing threat actor activity from {source_ip}.",
            external_references=[
                {"source_name": SESSION_SOURCE_NAME, "external_id": session_id}
            ],
        )
        objects.append(indicates_rel)
        self.stats["relationships_created"] += 1

        logging.debug(
            f"Created Indicator for {source_ip} with based-on and indicates relationships"
        )

        return objects

    def _create_observed_data_and_sighting(
        self,
        state: dict,
        intelligence: dict,
        source_ip_observable,
        target_ip_observables: List,
        network_traffic_objects: List,
        threat_actor: ThreatActor,
        indicator,
        session_id: str,
        bundle_objects: List,
        capping_label: Optional[str] = None,
    ):
        """Create Observed-Data and Sighting objects with proper references."""
        observed_data = ObservedDataManager.create_observed_data(
            state,
            intelligence,
            source_ip_observable,
            target_ip_observables,
            network_traffic_objects,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
            session_id=session_id,
            capping_label=capping_label,
        )

        if observed_data:
            bundle_objects.append(observed_data)
            self.stats["observed_data_created"] += 1

            sighting = Sighting(
                sighting_of_ref=indicator.id if indicator else threat_actor.id,
                where_sighted_refs=[self.author_standard_id],
                observed_data_refs=[observed_data.id],
                created_by_ref=self.author_standard_id,
                object_marking_refs=[self.tlp_clear_stix_id],
                count=1,
                first_seen=parse_iso_datetime(state["session_start_time"]),
                last_seen=parse_iso_datetime(state["last_activity_time"]),
                description=f"Malicious IP {state['source_ip']} sighted by PortSpoofPro CTI Platform during session {session_id}.",
                external_references=[
                    {"source_name": SESSION_SOURCE_NAME, "external_id": session_id}
                ],
                custom_properties={
                    "x_opencti_sighting_of_ref": source_ip_observable.id,
                },
            )
            bundle_objects.append(sighting)
            self.stats["sightings_created"] += 1

            logging.debug(
                "Created Sighting of Indicator with x_opencti_sighting_of_ref linking to Observable"
            )

    def _create_tools_and_attack_patterns(
        self,
        state: dict,
        intelligence: dict,
        threat_actor: ThreatActor,
        session_id: str,
    ) -> List:
        """Create Tool and AttackPattern objects with 'uses' relationships."""
        objects = []

        detected_tools = intelligence.get("detected_tools", [])
        techniques = intelligence.get("techniques", [])
        behaviors = intelligence.get("behaviors", [])
        attack_types = intelligence.get("attack_types", [])
        mitre_ttps = state.get("full_mitre_ttp_chain", [])

        tool_objects = DomainObjectManager.create_tool_objects(
            detected_tools=detected_tools,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
        )
        objects.extend(tool_objects)
        self.stats["tools_created"] += len(tool_objects)

        technique_patterns = DomainObjectManager.create_technique_attack_patterns(
            techniques=techniques,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
        )
        objects.extend(technique_patterns)
        self.stats["attack_patterns_created"] += len(technique_patterns)

        behavior_patterns = DomainObjectManager.create_behavior_attack_patterns(
            behaviors=behaviors,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
        )
        objects.extend(behavior_patterns)
        self.stats["attack_patterns_created"] += len(behavior_patterns)

        attack_patterns = DomainObjectManager.create_attack_attack_patterns(
            attack_types=attack_types,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
        )
        objects.extend(attack_patterns)
        self.stats["attack_patterns_created"] += len(attack_patterns)

        mitre_patterns = DomainObjectManager.create_mitre_attack_patterns(
            mitre_ttp_ids=mitre_ttps,
            created_by_ref=self.author_standard_id,
            marking_refs=[self.tlp_clear_stix_id],
        )
        objects.extend(mitre_patterns)
        self.stats["attack_patterns_created"] += len(mitre_patterns)

        all_attack_patterns = (
            technique_patterns + behavior_patterns + attack_patterns + mitre_patterns
        )

        relationships = DomainObjectManager.create_threat_actor_relationships(
            threat_actor_id=threat_actor.id,
            tools=tool_objects,
            attack_patterns=all_attack_patterns,
            marking_refs=[self.tlp_clear_stix_id],
        )
        objects.extend(relationships)
        self.stats["relationships_created"] += len(relationships)

        logging.info(
            f"Created {len(tool_objects)} Tools, {len(all_attack_patterns)} AttackPatterns "
            f"({len(technique_patterns)} techniques, {len(behavior_patterns)} behaviors, "
            f"{len(attack_patterns)} attacks, {len(mitre_patterns)} MITRE TTPs), "
            f"and {len(relationships)} relationships for session {session_id}"
        )

        return objects

    def _create_session_report(
        self, state: dict, intelligence: dict, bundle_objects: List, session_id: str
    ) -> Optional[Report]:
        """Create Report for ended session."""
        object_refs = [obj.id for obj in bundle_objects if hasattr(obj, "id")]
        report = self._create_report_stix2(
            state, intelligence, list(set(object_refs)), session_id
        )
        if report:
            self.stats["reports_created"] += 1
        return report

    def _send_bundle(self, bundle_objects: List, work_id: str, session_id: str):
        """Create and send STIX bundle to OpenCTI."""
        author_identity = Identity(
            id=PyctiIdentity.generate_id(
                name=AUTHOR_NAME, identity_class="organization"
            ),
            name=AUTHOR_NAME,
            identity_class="organization",
            description=AUTHOR_DESCRIPTION,
        )

        tlp_marking = TLP_WHITE

        bundle_objects_with_refs = [author_identity, tlp_marking] + bundle_objects

        bundle = Bundle(objects=bundle_objects_with_refs, allow_custom=True)
        bundle_json = bundle.serialize()

        bundle_json = add_empty_where_sighted_refs(bundle_json)

        logging.debug(
            f"Created STIX Bundle with {len(bundle_objects_with_refs)} objects "
            f"(+2 for Identity and Marking, {len(bundle_json)} bytes)"
        )

        self.helper.send_stix2_bundle(
            bundle_json,
            work_id=work_id,
            update=True,
            cleanup_inconsistent_bundle=True,
        )
        logging.info(
            f"Successfully sent STIX Bundle for session {session_id} "
            f"({len(bundle_objects_with_refs)} objects including Identity and Marking)"
        )

    def _complete_work(
        self, work_id: str, session_id: str, source_ip: str, object_count: int
    ):
        """Mark work as successfully processed."""
        message = f"Imported session {session_id} from {source_ip} - {object_count} objects created/updated."
        self.helper.api.work.to_processed(work_id, message)
        logging.info(f"Work {work_id} marked as processed")

    def _handle_sync_error(self, work_id: str, session_id: str, error: Exception):
        """Handle synchronization error."""
        self.stats["api_errors"] += 1
        error_message = (
            f"Failed to sync session {session_id}: {type(error).__name__}: {error}"
        )
        try:
            self.helper.api.work.to_processed(work_id, error_message, in_error=True)
        except:
            pass
        logging.error(
            f"Failed to sync session {session_id}: {type(error).__name__}: {error}",
            exc_info=True,
        )

    def _create_report_stix2(
        self,
        state: Dict[str, Any],
        intelligence: Dict[str, Any],
        object_refs: List[str],
        session_id: str,
    ) -> Optional[Report]:
        """Create Report STIX object for session summary."""
        try:
            source_ip = state["source_ip"]
            risk_score = safe_get_int(state, "risk_score", 0)
            alert_level = safe_get_int(state, "alert_level", 0)
            threat_level = map_threat_level(alert_level)

            tools_summary = ", ".join(intelligence.get("detected_tools", [])) or "None"
            ttps_summary = ", ".join(state.get("full_mitre_ttp_chain", [])) or "None"

            report_name = f"PortSpoofPro Session Report: {source_ip} ({session_id})"
            report_description = f"""
**PortSpoofPro Session Report**

**Attacker:** {source_ip}
**Session ID:** {session_id}
**Risk Score:** {risk_score}/1000
**Threat Level:** {threat_level}

**Detected Tools:** {tools_summary}
**MITRE ATT&CK TTPs:** {ttps_summary}

**Session Metrics:**
- Total Ports Probed: {safe_get_int(state, 'total_ports_seen', 0)}
- Total Hosts Probed: {safe_get_int(state, 'total_hosts_probed', 0)}
- Session Duration: {safe_get_float(state, 'total_session_duration_secs', 0):.2f} seconds
- Attacker Time Wasted: {safe_get_float(state, 'total_attacker_time_wasted_secs', 0):.2f} seconds

**Detection Summary:**
{len(state.get('full_detection_chain', []))} detection rules triggered

This report aggregates all STIX objects created for this PortSpoofPro session.
""".strip()

            report_id = generate_deterministic_stix_id(
                "report", {"name": report_name, "session_id": session_id}
            )

            report = Report(
                id=report_id,
                name=report_name,
                description=report_description,
                report_types=["threat-actor"],
                published=parse_iso_datetime(state.get("last_activity_time")),
                object_refs=object_refs,
                created_by_ref=self.author_standard_id,
                object_marking_refs=[self.tlp_clear_stix_id],
                labels=[
                    "portspoof-pro",
                    f"session:{session_id}",
                    f"threat:{threat_level.lower()}",
                    f"env:{ENVIRONMENT}",
                ],
                external_references=build_session_external_references(session_id),
            )

            return report

        except Exception as e:
            logging.error(f"Failed to create Report: {e}")
            return None
