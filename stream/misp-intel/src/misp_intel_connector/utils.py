"""
Utility functions for MISP Intel connector

This module contains helper functions for STIX to MISP conversion
using the misp-stix library with direct parsing (no temp files).
"""

import json
import traceback
from typing import Dict, Optional

from misp_stix_converter import ExternalSTIX2toMISPParser

# Supported container types for this connector
SUPPORTED_CONTAINER_TYPES = [
    "report",
    "grouping",
    "case-incident",
    "case-rfi",
    "case-rft",
    "x-opencti-case-incident",
    "x-opencti-case-rfi",
    "x-opencti-case-rft",
]


def is_supported_container_type(data: Dict) -> bool:
    """
    Check if the STIX object is a supported container type

    :param data: STIX object data
    :return: True if supported container type, False otherwise
    """
    try:
        obj_type = data.get("type", "").lower()
        return obj_type in SUPPORTED_CONTAINER_TYPES
    except Exception:
        return False


def get_container_type(data: Dict) -> Optional[str]:
    """
    Get the container type from STIX data

    :param data: STIX object data
    :return: Container type string or None
    """
    try:
        obj_type = data.get("type", "").lower()

        # Map all variations to simplified names
        type_mapping = {
            "x-opencti-case-incident": "case-incident",
            "x-opencti-case-rfi": "case-rfi",
            "x-opencti-case-rft": "case-rft",
            "case-incident": "case-incident",
            "case-rfi": "case-rfi",
            "case-rft": "case-rft",
            "report": "report",
            "grouping": "grouping",
        }

        return type_mapping.get(obj_type, None)

    except Exception:
        return None


def normalize_container_to_report(stix_bundle: Dict, helper) -> Dict:
    """
    Normalize OpenCTI custom containers to standard STIX 2.1 reports

    This converts case-incident, case-rfi, case-rft, grouping to report type
    and updates all references throughout the bundle.

    :param stix_bundle: STIX bundle to normalize
    :param helper: OpenCTI connector helper
    :return: Normalized STIX bundle
    """
    import copy

    # Make a deep copy to avoid modifying the original
    normalized_bundle = copy.deepcopy(stix_bundle)

    # Track ID mappings for updating references
    id_mappings = {}

    # Find and convert containers to reports
    for obj in normalized_bundle.get("objects", []):
        obj_type = obj.get("type", "").lower()
        obj_id = obj.get("id", "")

        if obj_type in [
            "case-incident",
            "case-rfi",
            "case-rft",
            "x-opencti-case-incident",
            "x-opencti-case-rfi",
            "x-opencti-case-rft",
            "grouping",
        ]:
            # Generate new report ID preserving the UUID part
            if "--" in obj_id:
                uuid_part = obj_id.split("--")[1]
                new_id = f"report--{uuid_part}"
            else:
                # Shouldn't happen but handle it
                new_id = obj_id

            # Store the mapping
            id_mappings[obj_id] = new_id

            # Convert to report
            obj["type"] = "report"
            obj["id"] = new_id

            # Ensure it has required report fields
            if "published" not in obj:
                obj["published"] = obj.get("created", "2024-01-01T00:00:00.000Z")

            if "object_refs" not in obj:
                # Initialize with empty list - the converter will handle it
                obj["object_refs"] = []

            helper.connector_logger.debug(
                f"Normalized {obj_type} to report",
                {"original_id": obj_id, "new_id": new_id},
            )

    # Update all references throughout the bundle
    if id_mappings:
        bundle_str = json.dumps(normalized_bundle)
        for old_id, new_id in id_mappings.items():
            bundle_str = bundle_str.replace(f'"{old_id}"', f'"{new_id}"')
        normalized_bundle = json.loads(bundle_str)

    return normalized_bundle


def convert_stix_bundle_to_misp_event(
    stix_bundle: Dict, helper, custom_uuid: Optional[str] = None
) -> Optional[Dict]:
    """
    Convert a STIX 2.1 bundle to MISP event format using misp-stix library

    This uses the ExternalSTIX2toMISPParser directly without temp files.

    :param stix_bundle: STIX 2.1 bundle containing the container and its references
    :param helper: OpenCTI connector helper instance
    :param custom_uuid: Optional custom UUID to use for the MISP event
    :return: MISP event data dictionary ready for PyMISP or None
    """
    try:
        # Validate bundle
        if not stix_bundle or "objects" not in stix_bundle:
            helper.connector_logger.error("Invalid STIX bundle: missing objects")
            return None

        # Find the main container object for logging (before normalization)
        original_container = None
        original_container_type = None
        for obj in stix_bundle.get("objects", []):
            if is_supported_container_type(obj):
                original_container = obj
                original_container_type = get_container_type(obj)
                break

        if original_container:
            helper.connector_logger.info(
                f"Converting {original_container_type} to MISP event",
                {"container_name": original_container.get("name", "Unknown")},
            )

        # Normalize OpenCTI custom containers to standard reports
        stix_bundle = normalize_container_to_report(stix_bundle, helper)

        # Ensure the bundle has spec_version for STIX 2.1
        if "spec_version" not in stix_bundle:
            stix_bundle["spec_version"] = "2.1"

        # Parse the dictionary bundle into a STIX 2.1 Bundle object
        # Use stix2.v21 explicitly to ensure STIX 2.1 parsing
        from stix2.v21 import Bundle

        bundle_json = json.dumps(stix_bundle)
        bundle_dict = json.loads(bundle_json)
        bundle_obj = Bundle(**bundle_dict, allow_custom=True)

        # Initialize the parser
        parser = ExternalSTIX2toMISPParser()

        # Load and parse the bundle
        parser.load_stix_bundle(bundle_obj)
        parser.parse_stix_bundle()

        # Get the MISP event from the parser
        if not hasattr(parser, "misp_event"):
            helper.connector_logger.error("Parser did not produce a MISP event")
            return None

        misp_event = parser.misp_event

        # Convert to dictionary format for PyMISP
        event_data = misp_event.to_dict()

        # Set custom UUID if provided
        if custom_uuid:
            event_data["uuid"] = custom_uuid

        # Ensure required fields have defaults
        if "info" not in event_data and original_container:
            event_data["info"] = original_container.get("name", "OpenCTI Import")
        elif "info" not in event_data:
            event_data["info"] = "OpenCTI Import"

        if "threat_level_id" not in event_data:
            event_data["threat_level_id"] = 2  # Medium by default

        if "analysis" not in event_data:
            event_data["analysis"] = 2  # Completed

        if "distribution" not in event_data:
            event_data["distribution"] = 1  # Community only

        # Map MISP event dict keys to PyMISP expected format
        # PyMISP expects lowercase keys for creating events
        if "Attribute" in event_data:
            event_data["attributes"] = event_data.pop("Attribute", [])

        if "Object" in event_data:
            event_data["objects"] = event_data.pop("Object", [])

        if "Tag" in event_data:
            tags = event_data.pop("Tag", [])
            event_data["tags"] = []
            for tag in tags:
                if isinstance(tag, dict):
                    event_data["tags"].append(tag.get("name", str(tag)))
                else:
                    event_data["tags"].append(str(tag))

        # Add OpenCTI-specific tags
        if "tags" not in event_data:
            event_data["tags"] = []

        event_data["tags"].append("source:opencti")
        # Use the original container type for the tag (before normalization)
        if original_container_type:
            event_data["tags"].append(f"opencti:type:{original_container_type}")

        # Clean up fields not needed for PyMISP
        for field in ["EventReport", "Galaxy", "GalaxyCluster"]:
            event_data.pop(field, None)

        helper.connector_logger.info(
            "Successfully converted STIX bundle to MISP event",
            {
                "event_uuid": event_data.get("uuid", "N/A"),
                "attributes_count": len(event_data.get("attributes", [])),
                "objects_count": len(event_data.get("objects", [])),
                "tags_count": len(event_data.get("tags", [])),
            },
        )

        return event_data

    except Exception as e:
        helper.connector_logger.error(
            f"Error converting STIX bundle to MISP: {str(e)}",
            {"trace": traceback.format_exc()},
        )
        return None


def get_creator_org_from_bundle(
    stix_bundle: Dict, container: Dict, helper
) -> Optional[str]:
    """
    Extract creator organization from STIX bundle

    This is kept for backward compatibility.

    :param stix_bundle: STIX bundle
    :param container: Container object
    :param helper: Connector helper
    :return: Organization name or None
    """
    try:
        # Check if container has created_by_ref
        created_by_ref = container.get("created_by_ref")
        if created_by_ref:
            # Find the identity object
            for obj in stix_bundle.get("objects", []):
                if obj.get("id") == created_by_ref and obj.get("type") == "identity":
                    return obj.get("name")

        # Check OpenCTI extension for creator organization
        extensions = container.get("extensions", {})
        for ext_key, ext_value in extensions.items():
            if "opencti" in ext_key.lower() and isinstance(ext_value, dict):
                if "created_by_ref" in ext_value:
                    created_by = ext_value["created_by_ref"]
                    # Find the identity
                    for obj in stix_bundle.get("objects", []):
                        if (
                            obj.get("id") == created_by
                            and obj.get("type") == "identity"
                        ):
                            return obj.get("name")

        return None

    except Exception as e:
        helper.connector_logger.debug(f"Could not extract creator org: {str(e)}")
        return None
