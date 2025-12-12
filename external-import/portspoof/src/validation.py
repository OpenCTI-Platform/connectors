"""Input validation for OpenCTI connector."""

import re
from typing import Any, Dict, List, Optional

from constants import VALID_EVENT_TYPES


class ValidationError(Exception):
    """Raised when input validation fails."""

    pass


def validate_session_state(state: Dict[str, Any]) -> None:
    """Validate full session state structure."""
    if not isinstance(state, dict):
        raise ValidationError(f"State must be a dictionary, got {type(state).__name__}")

    required_fields = [
        "session_id",
        "source_ip",
        "session_start_time",
        "last_activity_time",
        "last_event_type",
    ]

    for field in required_fields:
        if field not in state:
            raise ValidationError(f"Missing required field: {field}")
        if not state[field]:
            raise ValidationError(f"Field '{field}' cannot be empty")

    validate_session_id(state["session_id"])
    validate_ip_address(state["source_ip"])
    validate_event_type(state["last_event_type"])

    if "risk_score" in state and state["risk_score"] is not None:
        validate_numeric_range(state["risk_score"], "risk_score", min_val=0)

    if "alert_level" in state and state["alert_level"] is not None:
        validate_numeric_range(
            state["alert_level"], "alert_level", min_val=0, max_val=3
        )

    if "total_ports_seen" in state and state["total_ports_seen"] is not None:
        validate_numeric_range(state["total_ports_seen"], "total_ports_seen", min_val=0)

    if "total_hosts_probed" in state and state["total_hosts_probed"] is not None:
        validate_numeric_range(
            state["total_hosts_probed"], "total_hosts_probed", min_val=0
        )


def validate_session_id(session_id: str) -> None:
    """Validate session ID format."""
    if not isinstance(session_id, str):
        raise ValidationError(
            f"Session ID must be a string, got {type(session_id).__name__}"
        )

    if not session_id or len(session_id) < 1:
        raise ValidationError("Session ID cannot be empty")

    if len(session_id) > 256:
        raise ValidationError(f"Session ID too long: {len(session_id)} characters")


def validate_ip_address(ip_address: str) -> None:
    """Validate IPv4 or IPv6 address format."""
    if not isinstance(ip_address, str):
        raise ValidationError(
            f"IP address must be a string, got {type(ip_address).__name__}"
        )

    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    ipv6_pattern = r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"

    if not (re.match(ipv4_pattern, ip_address) or re.match(ipv6_pattern, ip_address)):
        raise ValidationError(f"Invalid IP address format: {ip_address}")


def validate_event_type(event_type: str) -> None:
    """Validate event type against allowed values."""
    if not isinstance(event_type, str):
        raise ValidationError(
            f"Event type must be a string, got {type(event_type).__name__}"
        )

    if event_type not in VALID_EVENT_TYPES:
        raise ValidationError(
            f"Invalid event type '{event_type}'. "
            f"Must be one of: {', '.join(VALID_EVENT_TYPES)}"
        )


def validate_numeric_range(
    value: Any,
    field_name: str,
    min_val: Optional[float] = None,
    max_val: Optional[float] = None,
) -> None:
    """Validate numeric value is within specified range."""
    if not isinstance(value, (int, float)):
        raise ValidationError(
            f"Field '{field_name}' must be numeric, got {type(value).__name__}"
        )

    if min_val is not None and value < min_val:
        raise ValidationError(
            f"Field '{field_name}' value {value} is below minimum {min_val}"
        )

    if max_val is not None and value > max_val:
        raise ValidationError(
            f"Field '{field_name}' value {value} exceeds maximum {max_val}"
        )


def validate_intelligence_data(intelligence: Dict[str, Any]) -> None:
    """Validate extracted intelligence data structure."""
    if not isinstance(intelligence, dict):
        raise ValidationError(
            f"Intelligence must be a dictionary, got {type(intelligence).__name__}"
        )

    expected_keys = [
        "detected_tools",
        "techniques",
        "behaviors",
        "attack_types",
        "scan_patterns",
        "evidence_attributes",
    ]

    for key in expected_keys:
        if key not in intelligence:
            raise ValidationError(f"Missing expected intelligence key: {key}")

        if key in ["detected_tools", "techniques", "behaviors", "attack_types"]:
            if not isinstance(intelligence[key], list):
                raise ValidationError(
                    f"Intelligence field '{key}' must be a list, "
                    f"got {type(intelligence[key]).__name__}"
                )

        if key in ["scan_patterns", "evidence_attributes"]:
            if not isinstance(intelligence[key], dict):
                raise ValidationError(
                    f"Intelligence field '{key}' must be a dict, "
                    f"got {type(intelligence[key]).__name__}"
                )


def validate_stix_id(stix_id: str, expected_type: Optional[str] = None) -> None:
    """Validate STIX ID format."""
    if not isinstance(stix_id, str):
        raise ValidationError(f"STIX ID must be a string, got {type(stix_id).__name__}")

    pattern = (
        r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )

    if not re.match(pattern, stix_id):
        raise ValidationError(f"Invalid STIX ID format: {stix_id}")

    if expected_type:
        actual_type = stix_id.split("--")[0]
        if actual_type != expected_type:
            raise ValidationError(
                f"STIX ID type mismatch: expected '{expected_type}', got '{actual_type}'"
            )


def sanitize_string(value: str, max_length: Optional[int] = None) -> str:
    """Sanitize string value for safe processing."""
    if not isinstance(value, str):
        value = str(value)

    value = "".join(char for char in value if ord(char) >= 32 or char in "\n\r\t")
    value = value.strip()

    if max_length and len(value) > max_length:
        value = value[:max_length]

    return value


def validate_list_of_strings(
    items: List[str], field_name: str, max_items: Optional[int] = None
) -> None:
    """Validate list contains only strings."""
    if not isinstance(items, list):
        raise ValidationError(
            f"Field '{field_name}' must be a list, got {type(items).__name__}"
        )

    for i, item in enumerate(items):
        if not isinstance(item, str):
            raise ValidationError(
                f"Field '{field_name}[{i}]' must be a string, got {type(item).__name__}"
            )

    if max_items and len(items) > max_items:
        raise ValidationError(
            f"Field '{field_name}' has too many items: {len(items)} > {max_items}"
        )
