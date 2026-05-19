"""Helper utilities for OpenCTI connector."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from constants import (
    ATTACK_PREFIX,
    BEHAVIOR_PREFIX,
    DEFAULT_THREAT_LEVEL,
    ENVIRONMENT,
    FINGERPRINT_PREFIX,
    TECHNIQUE_PREFIX,
    THREAT_LEVEL_MAP,
)


def calculate_opencti_score(alert_level: int) -> int:
    """Map alert level (0-3) to OpenCTI score (0-100)."""
    mapping = {3: 100, 2: 75, 1: 50, 0: 25}
    return mapping.get(alert_level, 0)


def map_threat_level(alert_level: int) -> str:
    """Map numeric alert level to threat level string."""
    return THREAT_LEVEL_MAP.get(alert_level, DEFAULT_THREAT_LEVEL)


def parse_iso_datetime(iso_string: Optional[str]) -> datetime:
    """Parse ISO 8601 datetime string to timezone-aware datetime in UTC."""
    if not iso_string:
        return datetime.now(timezone.utc)

    normalized = iso_string.replace("Z", "+00:00")

    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError as e:
        logging.warning(
            f"Failed to parse datetime '{iso_string}': {e}. Using current time."
        )
        return datetime.now(timezone.utc)


def datetime_serializer(obj: Any) -> str:
    """JSON serializer for datetime objects."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def generate_labels(
    state: Dict[str, Any],
    intelligence: Dict[str, Any],
    event_type: Optional[str] = None,
) -> List[str]:
    """Generate labels for STIX objects. High-cardinality metrics only added on final event."""
    labels = ["portspoof-pro"]
    labels.append(f"env:{ENVIRONMENT}")

    alert_level = state.get("alert_level", 0)
    if alert_level is not None:
        labels.append(f"threat:{map_threat_level(alert_level).lower()}")

    is_final_event = event_type == "scanner_session_ended" or event_type is None
    if is_final_event:
        sensor_id = state.get("sensor_id", "none")
        sensor_hostname = state.get("sensor_hostname", "none")
        session_id = state["session_id"]

        session_label = f"session:{sensor_id}:{session_id}"

        labels.extend(
            [
                session_label,
                f"risk-score:{int(state.get('risk_score', 0))}",
                f"sensor:{sensor_id}",
                f"sensor-host:{sensor_hostname}",
            ]
        )

    return labels


def build_external_reference(source_name: str, external_id: str) -> Dict[str, str]:
    """Build external reference dictionary."""
    return {"source_name": source_name, "external_id": external_id}


def build_session_external_references(
    session_id: str, additional_refs: Optional[List[Dict[str, str]]] = None
) -> List[Dict[str, str]]:
    """Build external references for session objects."""
    from constants import SESSION_SOURCE_NAME

    refs = [build_external_reference(SESSION_SOURCE_NAME, session_id)]

    if additional_refs:
        refs.extend(additional_refs)

    return refs


def extract_tools_from_detections(detections: List[Dict[str, Any]]) -> List[str]:
    """Extract tool names from detection chain using fingerprint pattern."""
    tools = []

    for detection in detections:
        name = detection.get("name", "")
        if name.startswith(FINGERPRINT_PREFIX):
            tool_name = name.replace(FINGERPRINT_PREFIX, "")
            if tool_name and tool_name not in tools:
                tools.append(tool_name)

    return tools


def extract_techniques_from_detections(detections: List[Dict[str, Any]]) -> List[str]:
    """Extract technique names from detection chain."""
    techniques = []

    for detection in detections:
        name = detection.get("name", "")
        if name.startswith(TECHNIQUE_PREFIX):
            technique_name = name.replace(TECHNIQUE_PREFIX, "")
            if technique_name and technique_name not in techniques:
                techniques.append(technique_name)

    return techniques


def extract_behaviors_from_detections(detections: List[Dict[str, Any]]) -> List[str]:
    """Extract behavior patterns from detection chain."""
    behaviors = []

    for detection in detections:
        name = detection.get("name", "")
        if name.startswith(BEHAVIOR_PREFIX):
            behavior_name = name.replace(BEHAVIOR_PREFIX, "")
            if behavior_name and behavior_name not in behaviors:
                behaviors.append(behavior_name)

    return behaviors


def extract_attack_types_from_detections(detections: List[Dict[str, Any]]) -> List[str]:
    """Extract attack types from detection chain."""
    attack_types = []

    for detection in detections:
        name = detection.get("name", "")
        if name.startswith(ATTACK_PREFIX):
            attack_type = name.replace(ATTACK_PREFIX, "")
            if attack_type and attack_type not in attack_types:
                attack_types.append(attack_type)

    return attack_types


def aggregate_detection_attributes(detections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate attributes from detection chain. Keeps max for numeric, latest for strings."""
    attributes = {}

    for detection in detections:
        attrs = detection.get("attributes", {})

        for attr_name, attr_value in attrs.items():
            if isinstance(attr_value, (int, float)):
                attributes[attr_name] = max(attributes.get(attr_name, 0), attr_value)
            else:
                attributes[attr_name] = attr_value

    return attributes


def calculate_port_scan_metrics(
    probed_ports_detail: Optional[Dict[str, List[int]]],
) -> Dict[str, int]:
    """Calculate port counts by scan technique."""
    if not probed_ports_detail:
        probed_ports_detail = {}

    return {
        "syn_ports": len(probed_ports_detail.get("syn_scan", [])),
        "fin_ports": len(probed_ports_detail.get("fin_scan", [])),
        "null_ports": len(probed_ports_detail.get("null_scan", [])),
        "xmas_ports": len(probed_ports_detail.get("xmas_scan", [])),
        "ack_ports": len(probed_ports_detail.get("ack_scan", [])),
        "udp_ports": len(probed_ports_detail.get("udp_port_scan", [])),
        "full_connect_ports": len(probed_ports_detail.get("full_connect_scan", [])),
    }


def calculate_unique_tcp_ports(
    probed_ports_detail: Optional[Dict[str, List[int]]],
) -> int:
    """Calculate unique TCP ports across all techniques (no double-counting)."""
    if not probed_ports_detail:
        return 0

    tcp_techniques = [
        "syn_scan",
        "fin_scan",
        "null_scan",
        "xmas_scan",
        "ack_scan",
        "full_connect_scan",
    ]

    unique_tcp_ports: set = set()
    for technique in tcp_techniques:
        ports = probed_ports_detail.get(technique, [])
        unique_tcp_ports.update(ports)

    return len(unique_tcp_ports)


def format_port_list_by_technique(
    probed_ports_detail: Optional[Dict[str, List[int]]],
    max_ports_per_technique: int = 10,
) -> str:
    """Format port lists by scan technique with truncation."""
    if not probed_ports_detail:
        return ""

    technique_names = {
        "syn_scan": "SYN Scan",
        "fin_scan": "FIN Scan",
        "null_scan": "NULL Scan",
        "xmas_scan": "XMAS Scan",
        "ack_scan": "ACK Scan",
        "udp_port_scan": "UDP Scan",
        "full_connect_scan": "Full Connect Scan",
    }

    lines = []

    for technique_key, display_name in technique_names.items():
        ports = probed_ports_detail.get(technique_key, [])
        if not ports:
            continue

        total_count = len(ports)
        shown_ports = ports[:max_ports_per_technique]
        remaining = total_count - len(shown_ports)

        port_str = ", ".join(str(p) for p in shown_ports)

        if remaining > 0:
            line = f"  - {display_name} ({total_count} ports): {port_str} ... +{remaining} more"
        else:
            line = f"  - {display_name} ({total_count} ports): {port_str}"

        lines.append(line)

    return "\n".join(lines) if lines else ""


def calculate_time_wasted_minutes(time_wasted_secs: Optional[float]) -> int:
    """Convert time wasted (seconds) to minutes."""
    from constants import SECONDS_PER_MINUTE

    if time_wasted_secs is None or time_wasted_secs < 0:
        return 0

    return int(time_wasted_secs / SECONDS_PER_MINUTE)


def calculate_port_volume_category(total_ports_seen: int) -> str:
    """Categorize port scanning volume."""
    if total_ports_seen < 100:
        return "low"
    elif total_ports_seen < 1000:
        return "medium"
    elif total_ports_seen < 10000:
        return "high"
    else:
        return "extreme"


def calculate_duration_minutes(duration_secs: Optional[float]) -> int:
    """Convert duration (seconds) to minutes."""
    from constants import SECONDS_PER_MINUTE

    if duration_secs is None or duration_secs < 0:
        return 0

    return int(duration_secs / SECONDS_PER_MINUTE)


def format_mitre_ttp_url(ttp_id: str) -> str:
    """Generate MITRE ATT&CK URL from TTP ID (handles sub-techniques)."""
    from constants import MITRE_ATTACK_BASE_URL

    formatted_id = ttp_id.replace(".", "/")
    return f"{MITRE_ATTACK_BASE_URL}/{formatted_id}/"


def format_mitre_ttp_name(ttp_id: str) -> str:
    """Generate display name for MITRE TTP."""
    return f"MITRE ATT&CK {ttp_id}"


def safe_get_float(data: Dict[str, Any], key: str, default: float = 0.0) -> float:
    """Extract float from dict with fallback."""
    value = data.get(key)
    if value is None:
        return default

    try:
        return float(value)
    except (ValueError, TypeError):
        logging.warning(f"Failed to convert '{key}' value to float: {value}")
        return default


def safe_get_int(data: Dict[str, Any], key: str, default: int = 0) -> int:
    """Extract int from dict with fallback."""
    value = data.get(key)
    if value is None:
        return default

    try:
        return int(value)
    except (ValueError, TypeError):
        logging.warning(f"Failed to convert '{key}' value to int: {value}")
        return default


def safe_get_string(data: Dict[str, Any], key: str, default: str = "") -> str:
    """Extract string from dict with fallback."""
    value = data.get(key)
    if value is None:
        return default

    return str(value)
