"""
Utility functions for the MISP Intel connector

This module provides helper functions for the MISP Intel connector,
including comprehensive STIX 2.1 to MISP conversion with full support
for all OpenCTI entity types, observables, indicators, and sightings.
"""

import traceback
from typing import Dict, Optional

from .stix_to_misp_converter import STIXtoMISPConverter

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


def is_supported_container_type(stix_object: Dict) -> bool:
    """
    Check if a STIX object is a supported container type

    :param stix_object: STIX object to check
    :return: True if supported container type
    """
    if not stix_object:
        return False

    obj_type = stix_object.get("type", "").lower()
    return obj_type in SUPPORTED_CONTAINER_TYPES


def get_container_type(stix_object: Dict) -> Optional[str]:
    """
    Get the container type from a STIX object

    This normalizes various container type formats to a clean string.

    :param stix_object: STIX object
    :return: Container type string or None
    """
    if not stix_object:
        return None

    obj_type = stix_object.get("type", "").lower()

    # Normalize the type
    if obj_type.startswith("x-opencti-"):
        # Remove x-opencti- prefix
        return obj_type.replace("x-opencti-", "")
    elif obj_type.startswith("case-"):
        # Keep case types as is
        return obj_type
    elif obj_type in ["report", "grouping"]:
        # Standard STIX types
        return obj_type
    else:
        return None


def convert_stix_bundle_to_misp_event(
    stix_bundle: Dict, helper, config, custom_uuid: Optional[str] = None
) -> Optional[Dict]:
    """
    Convert a STIX 2.1 bundle to MISP event format using custom converter

    This provides comprehensive conversion including:
    - All OpenCTI entity types mapped to MISP galaxies
    - Full indicator pattern parsing and conversion
    - Complete observable type support
    - STIX 2.1 sightings conversion
    - Fallback to tags when galaxy mapping is not possible

    :param stix_bundle: STIX 2.1 bundle containing the container and its references
    :param helper: OpenCTI connector helper instance
    :param config: Connector configuration
    :param custom_uuid: Optional custom UUID to use for the MISP event
    :return: MISP event data dictionary ready for PyMISP or None
    """
    try:
        # Validate bundle
        if not stix_bundle or "objects" not in stix_bundle:
            helper.connector_logger.error("Invalid STIX bundle: missing objects")
            return None

        # Find the main container object for logging
        container = None
        for obj in stix_bundle.get("objects", []):
            if is_supported_container_type(obj):
                container = obj
                break

        if container:
            container_type = get_container_type(container)
            helper.connector_logger.info(
                f"Converting {container_type} to MISP event",
                {"container_name": container.get("name", "Unknown")},
            )
        else:
            helper.connector_logger.warning(
                "No supported container found in STIX bundle, attempting conversion anyway"
            )

        # Use our custom converter
        converter = STIXtoMISPConverter(helper, config)
        event_data = converter.convert_bundle_to_event(stix_bundle, custom_uuid)

        if event_data:
            helper.connector_logger.info(
                "Successfully converted STIX bundle to MISP event",
                {
                    "event_uuid": event_data.get("uuid", "N/A"),
                    "attributes_count": len(event_data.get("Attribute", [])),
                    "objects_count": len(event_data.get("Object", [])),
                    "tags_count": len(event_data.get("Tag", [])),
                },
            )
            return event_data
        else:
            helper.connector_logger.error("Conversion returned no data")
            return None

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

    This looks for the identity that created the container object.

    :param stix_bundle: STIX bundle
    :param container: Container object
    :param helper: OpenCTI connector helper
    :return: Organization name or None
    """
    try:
        # Check for created_by_ref in container
        created_by_ref = container.get("created_by_ref")
        if created_by_ref:
            # Find the identity object
            for obj in stix_bundle.get("objects", []):
                if obj.get("id") == created_by_ref and obj.get("type") == "identity":
                    return obj.get("name")

        # Check OpenCTI extension for creator organization
        extensions = container.get("extensions", {})
        opencti_ext = extensions.get(
            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
        )
        if opencti_ext:
            # Look for creator_id in extension
            creator_id = opencti_ext.get("creator_id")
            if creator_id:
                # Find the identity with this ID
                for obj in stix_bundle.get("objects", []):
                    created_by = obj.get("created_by_ref")
                    if created_by:
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
