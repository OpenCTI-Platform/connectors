"""
Utility functions for Splunk SOAR Push connector
"""

from typing import Dict


def get_entity_type(stix_data: Dict) -> str:
    """
    Get the entity type from STIX data
    :param stix_data: STIX entity data
    :return: Entity type string
    """
    stix_type = stix_data.get("type", "")

    # Map STIX types to simplified types
    if stix_type == "incident" or stix_type == "x-opencti-incident":
        return "incident"
    elif stix_type == "report":
        return "report"
    elif stix_type == "grouping":
        return "grouping"
    elif stix_type == "x-opencti-case-incident":
        return "case-incident"
    elif stix_type == "x-opencti-case-rfi":
        return "case-rfi"
    elif stix_type == "x-opencti-case-rft":
        return "case-rft"
    else:
        return stix_type


def is_incident_entity(stix_data: Dict) -> bool:
    """
    Check if STIX data represents an incident
    :param stix_data: STIX entity data
    :return: True if incident
    """
    stix_type = stix_data.get("type", "")
    return stix_type in ["incident", "x-opencti-incident"]


def is_supported_container_type(stix_data: Dict) -> bool:
    """
    Check if STIX data represents a supported container type
    :param stix_data: STIX entity data
    :return: True if supported container type
    """
    stix_type = stix_data.get("type", "")
    return stix_type in [
        "report",
        "grouping",
        "case-incident",
        "case-rfi",
        "case-rft",
        "x-opencti-case-incident",
        "x-opencti-case-rfi",
        "x-opencti-case-rft",
    ]


def get_severity_from_stix(stix_data: Dict) -> str:
    """
    Map STIX severity to SOAR severity
    :param stix_data: STIX entity data
    :return: SOAR severity string
    """
    severity = stix_data.get("severity", "").lower()

    # Map to SOAR severity levels
    severity_mapping = {
        "critical": "high",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "low",
        "unknown": "low",
    }

    return severity_mapping.get(severity, "medium")


def get_status_from_stix(stix_data: Dict) -> str:
    """
    Map STIX/OpenCTI status to SOAR status
    :param stix_data: STIX entity data
    :return: SOAR status string
    """
    # Check OpenCTI extensions for workflow status
    extensions = stix_data.get("extensions", {})
    opencti_ext = extensions.get(
        "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba", {}
    )

    workflow_id = opencti_ext.get("workflow_id")
    if workflow_id:
        # Map OpenCTI workflow IDs to SOAR statuses
        # These are examples, adjust based on actual OpenCTI workflow IDs
        workflow_mapping = {
            "new": "new",
            "in-progress": "open",
            "resolved": "closed",
            "dismissed": "closed",
        }

        for key, value in workflow_mapping.items():
            if key in workflow_id.lower():
                return value

    # Default to new
    return "new"


def extract_labels_as_tags(stix_data: Dict) -> list:
    """
    Extract labels from STIX data to use as tags
    :param stix_data: STIX entity data
    :return: List of tag strings
    """
    tags = []

    # Get labels from STIX
    labels = stix_data.get("labels", [])
    tags.extend(labels)

    # Get labels from OpenCTI extensions
    extensions = stix_data.get("extensions", {})
    opencti_ext = extensions.get(
        "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba", {}
    )

    if "labels" in opencti_ext:
        for label in opencti_ext.get("labels", []):
            if isinstance(label, dict):
                tag = label.get("value", label.get("name", ""))
            else:
                tag = str(label)
            if tag and tag not in tags:
                tags.append(tag)

    return tags


def sanitize_for_soar(text: str, max_length: int = None) -> str:
    """
    Sanitize text for SOAR API
    :param text: Input text
    :param max_length: Maximum length
    :return: Sanitized text
    """
    if not text:
        return ""

    # Remove null bytes
    text = text.replace("\x00", "")

    # Truncate if needed
    if max_length and len(text) > max_length:
        text = text[: max_length - 3] + "..."

    return text
