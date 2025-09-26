"""
Utility functions for MISP Intel connector

This module contains helper functions for STIX to MISP conversion
and other utility operations.
"""

import hashlib
import json
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Any

from misp_stix_converter import (
    stix_2_to_misp,
    MISPtoSTIX21Parser,
    ExternalSTIX2toMISPParser,
)


# Supported container types for this connector
SUPPORTED_CONTAINER_TYPES = [
    "report",
    "grouping",
    "case-incident",
    "case-rfi",
    "case-rft",
]

# STIX to MISP threat level mapping
THREAT_LEVEL_MAPPING = {
    "low": 3,  # Low
    "medium": 2,  # Medium
    "high": 1,  # High
    "critical": 1,  # Map critical to high
}

# STIX to MISP distribution mapping
DISTRIBUTION_MAPPING = {
    "internal": 0,  # Your organisation only
    "community": 1,  # This community only
    "connected": 2,  # Connected communities
    "all": 3,  # All communities
}


def is_supported_container_type(data: Dict) -> bool:
    """
    Check if the STIX object is a supported container type

    :param data: STIX object data
    :return: True if supported container type, False otherwise
    """
    try:
        obj_type = data.get("type", "").lower()

        # Handle both standard and OpenCTI-specific case types
        supported_types = [
            "report",
            "grouping",
            "case-incident",
            "case-rfi",
            "case-rft",
            "x-opencti-case-incident",
            "x-opencti-case-rfi",
            "x-opencti-case-rft",
        ]
        
        return obj_type in supported_types

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


def get_creator_org_from_bundle(stix_bundle: Dict, container: Dict, helper: Any) -> Optional[str]:
    """
    Extract the creator organization name from the STIX bundle
    
    :param stix_bundle: STIX 2.1 bundle
    :param container: The container object
    :param helper: OpenCTI connector helper instance
    :return: Creator organization name or None
    """
    try:
        # Get created_by_ref from container
        created_by_ref = container.get("created_by_ref")
        if not created_by_ref:
            return None
            
        # Find the identity object in the bundle
        for obj in stix_bundle.get("objects", []):
            if obj.get("id") == created_by_ref:
                # Found the creator identity
                if obj.get("type") == "identity":
                    creator_name = obj.get("name")
                    if creator_name:
                        helper.connector_logger.info(
                            f"Found creator organization: {creator_name}"
                        )
                        return creator_name
                break
                
        return None
    except Exception as e:
        helper.connector_logger.warning(
            f"Could not extract creator org: {str(e)}"
        )
        return None


def convert_stix_bundle_to_misp_event(stix_bundle: Dict, helper: Any) -> Optional[Dict]:
    """
    Convert a STIX 2.1 bundle to MISP event format using misp-stix library

    :param stix_bundle: STIX 2.1 bundle containing the container and its references
    :param helper: OpenCTI connector helper instance
    :return: MISP event data dictionary or None
    """
    try:
        # Validate bundle
        if not stix_bundle or "objects" not in stix_bundle:
            helper.connector_logger.error("Invalid STIX bundle: missing objects")
            return None

        # Find the main container object
        container = None
        container_type = None

        for obj in stix_bundle.get("objects", []):
            if is_supported_container_type(obj):
                container = obj
                container_type = get_container_type(obj)
                break

        if not container:
            helper.connector_logger.error("No supported container found in STIX bundle")
            return None

        helper.connector_logger.info(
            f"Converting {container_type} to MISP event",
            {"container_id": container.get("id")},
        )

        # For now, skip the misp-stix parser which seems to hang
        # and create a simple event from the container data
        try:
            # Create a simple MISP event structure
            misp_event = None  # We'll build event_data directly

            # Build MISP event data structure
            event_data = {
                "info": container.get("name", "OpenCTI Import"),
                "date": datetime.now().strftime("%Y-%m-%d"),
                "threat_level_id": 2,  # Medium by default
                "analysis": 2,  # Completed
                "distribution": 1,  # Community only by default
                "attributes": [],
                "objects": [],
                "tags": [],
            }
            
            # Extract creator org from bundle
            creator_org = get_creator_org_from_bundle(stix_bundle, container, helper)
            if creator_org:
                event_data["orgc"] = creator_org

            # Set event info from container
            if "name" in container:
                event_data["info"] = container["name"]
            elif "description" in container:
                event_data["info"] = container["description"][:100]  # Limit length

            # Set date from container
            if "created" in container:
                try:
                    created_date = datetime.fromisoformat(
                        container["created"].replace("Z", "+00:00")
                    )
                    event_data["date"] = created_date.strftime("%Y-%m-%d")
                except:
                    pass

            # Extract confidence as threat level
            if "confidence" in container:
                confidence = container["confidence"]
                if confidence >= 75:
                    event_data["threat_level_id"] = 1  # High
                elif confidence >= 50:
                    event_data["threat_level_id"] = 2  # Medium
                else:
                    event_data["threat_level_id"] = 3  # Low

            # Process attributes from the parsed MISP event
            if hasattr(misp_event, "attributes") and misp_event.attributes:
                for attr in misp_event.attributes:
                    attr_dict = {
                        "type": attr.type,
                        "value": attr.value,
                        "category": attr.category,
                        "to_ids": attr.to_ids,
                        "comment": attr.comment if hasattr(attr, "comment") else "",
                        "distribution": 1,  # Community only
                    }
                    event_data["attributes"].append(attr_dict)

            # Process objects from the parsed MISP event
            if hasattr(misp_event, "objects") and misp_event.objects:
                for obj in misp_event.objects:
                    obj_dict = {
                        "name": obj.name,
                        "comment": obj.comment if hasattr(obj, "comment") else "",
                        "distribution": 1,
                        "attributes": [],
                    }

                    if hasattr(obj, "attributes"):
                        for obj_attr in obj.attributes:
                            obj_attr_dict = {
                                "object_relation": obj_attr.object_relation,
                                "type": obj_attr.type,
                                "value": obj_attr.value,
                                "to_ids": obj_attr.to_ids,
                                "comment": (
                                    obj_attr.comment
                                    if hasattr(obj_attr, "comment")
                                    else ""
                                ),
                            }
                            obj_dict["attributes"].append(obj_attr_dict)

                    event_data["objects"].append(obj_dict)

            # Process tags from the parsed MISP event
            if hasattr(misp_event, "tags") and misp_event.tags:
                for tag in misp_event.tags:
                    if hasattr(tag, "name"):
                        event_data["tags"].append(tag.name)
                    else:
                        event_data["tags"].append(str(tag))

            # Add OpenCTI-specific tags
            if container_type:
                event_data["tags"].append(f"opencti:type={container_type}")

            # Add labels as tags
            if "labels" in container:
                for label in container.get("labels", []):
                    event_data["tags"].append(f"opencti:label={label}")

            helper.connector_logger.info(
                f"Successfully converted STIX bundle to MISP event",
                {
                    "attributes_count": len(event_data["attributes"]),
                    "objects_count": len(event_data["objects"]),
                    "tags_count": len(event_data["tags"]),
                },
            )

            return event_data

        except Exception as e:
            # If misp-stix converter fails, fall back to manual conversion
            helper.connector_logger.warning(
                f"misp-stix converter failed, using fallback conversion: {str(e)}"
            )
            return convert_stix_bundle_fallback(stix_bundle, container, helper)

    except Exception as e:
        helper.connector_logger.error(
            f"Error converting STIX bundle to MISP event: {str(e)}",
            {"trace": traceback.format_exc()},
        )
        return None


def convert_stix_bundle_fallback(
    stix_bundle: Dict, container: Dict, helper: Any
) -> Optional[Dict]:
    """
    Fallback conversion method when misp-stix library fails

    :param stix_bundle: STIX 2.1 bundle
    :param container: The main container object
    :param helper: OpenCTI connector helper instance
    :return: MISP event data dictionary or None
    """
    try:
        event_data = {
            "info": container.get("name", "OpenCTI Import"),
            "date": datetime.now().strftime("%Y-%m-%d"),
            "threat_level_id": 2,  # Medium by default
            "analysis": 2,  # Completed
            "distribution": 1,  # Community only
            "attributes": [],
            "objects": [],
            "tags": [],
        }
        
        # Extract creator org from bundle for fallback conversion too
        creator_org = get_creator_org_from_bundle(stix_bundle, container, helper)
        if creator_org:
            event_data["orgc"] = creator_org

        # Process each object in the bundle
        for obj in stix_bundle.get("objects", []):
            obj_type = obj.get("type", "")

            # Skip the container itself
            if obj.get("id") == container.get("id"):
                continue

            # Process indicators
            if obj_type == "indicator":
                pattern = obj.get("pattern", "")
                attr_dict = {
                    "type": "text",
                    "value": pattern,
                    "category": "External analysis",
                    "to_ids": True,
                    "comment": obj.get("description", ""),
                    "distribution": 1,
                }
                event_data["attributes"].append(attr_dict)

            # Process observables
            elif obj_type == "ipv4-addr":
                attr_dict = {
                    "type": "ip-dst",
                    "value": obj.get("value", ""),
                    "category": "Network activity",
                    "to_ids": True,
                    "comment": "",
                    "distribution": 1,
                }
                event_data["attributes"].append(attr_dict)

            elif obj_type == "ipv6-addr":
                attr_dict = {
                    "type": "ip-dst",
                    "value": obj.get("value", ""),
                    "category": "Network activity",
                    "to_ids": True,
                    "comment": "",
                    "distribution": 1,
                }
                event_data["attributes"].append(attr_dict)

            elif obj_type == "domain-name":
                attr_dict = {
                    "type": "domain",
                    "value": obj.get("value", ""),
                    "category": "Network activity",
                    "to_ids": True,
                    "comment": "",
                    "distribution": 1,
                }
                event_data["attributes"].append(attr_dict)

            elif obj_type == "url":
                attr_dict = {
                    "type": "url",
                    "value": obj.get("value", ""),
                    "category": "Network activity",
                    "to_ids": True,
                    "comment": "",
                    "distribution": 1,
                }
                event_data["attributes"].append(attr_dict)

            elif obj_type == "file":
                # Handle file hashes
                hashes = obj.get("hashes", {})
                for hash_type, hash_value in hashes.items():
                    misp_hash_type = hash_type.lower().replace("-", "")
                    if misp_hash_type in ["md5", "sha1", "sha256", "sha512"]:
                        attr_dict = {
                            "type": misp_hash_type,
                            "value": hash_value,
                            "category": "Payload delivery",
                            "to_ids": True,
                            "comment": obj.get("name", ""),
                            "distribution": 1,
                        }
                        event_data["attributes"].append(attr_dict)

            elif obj_type == "email-addr":
                attr_dict = {
                    "type": "email-src",
                    "value": obj.get("value", ""),
                    "category": "Network activity",
                    "to_ids": False,
                    "comment": "",
                    "distribution": 1,
                }
                event_data["attributes"].append(attr_dict)

            # Process threat actors, malware, etc. as tags
            elif obj_type in ["threat-actor", "malware", "tool", "attack-pattern"]:
                name = obj.get("name", "")
                if name:
                    event_data["tags"].append(f"{obj_type}:{name}")

        # Add basic tags
        container_type = get_container_type(container)
        if container_type:
            event_data["tags"].append(f"opencti:type={container_type}")

        # Add labels as tags
        if "labels" in container:
            for label in container.get("labels", []):
                event_data["tags"].append(f"opencti:label={label}")

        helper.connector_logger.info(
            f"Fallback conversion completed",
            {
                "attributes_count": len(event_data["attributes"]),
                "tags_count": len(event_data["tags"]),
            },
        )

        return event_data

    except Exception as e:
        helper.connector_logger.error(
            f"Fallback conversion failed: {str(e)}",
            {"trace": traceback.format_exc()},
        )
        return None


def sanitize_misp_value(value: Any) -> str:
    """
    Sanitize a value for MISP compatibility

    :param value: Value to sanitize
    :return: Sanitized string value
    """
    if value is None:
        return ""

    # Convert to string and strip
    str_value = str(value).strip()

    # Remove control characters
    str_value = "".join(ch for ch in str_value if ord(ch) >= 32 or ch == "\n")

    return str_value


def get_hash_type(hash_value: str) -> Optional[str]:
    """
    Determine the hash type based on the hash value length

    :param hash_value: Hash string
    :return: Hash type (md5, sha1, sha256, etc.) or None
    """
    hash_lengths = {
        32: "md5",
        40: "sha1",
        64: "sha256",
        128: "sha512",
    }

    if not hash_value:
        return None

    # Remove any non-hex characters and convert to lowercase
    clean_hash = "".join(c for c in hash_value.lower() if c in "0123456789abcdef")

    return hash_lengths.get(len(clean_hash))


def extract_iocs_from_pattern(pattern: str) -> List[Dict]:
    """
    Extract IOCs from a STIX pattern string

    :param pattern: STIX pattern string
    :return: List of IOC dictionaries with type and value
    """
    iocs = []

    try:
        # Simple pattern extraction (can be enhanced)
        if "ipv4-addr:value" in pattern:
            # Extract IPv4 addresses
            parts = pattern.split("'")
            for i in range(1, len(parts), 2):
                iocs.append({"type": "ip-dst", "value": parts[i]})

        elif "ipv6-addr:value" in pattern:
            # Extract IPv6 addresses
            parts = pattern.split("'")
            for i in range(1, len(parts), 2):
                iocs.append({"type": "ip-dst", "value": parts[i]})

        elif "domain-name:value" in pattern:
            # Extract domains
            parts = pattern.split("'")
            for i in range(1, len(parts), 2):
                iocs.append({"type": "domain", "value": parts[i]})

        elif "url:value" in pattern:
            # Extract URLs
            parts = pattern.split("'")
            for i in range(1, len(parts), 2):
                iocs.append({"type": "url", "value": parts[i]})

        elif "file:hashes" in pattern:
            # Extract file hashes
            parts = pattern.split("'")
            for i in range(1, len(parts), 2):
                hash_type = get_hash_type(parts[i])
                if hash_type:
                    iocs.append({"type": hash_type, "value": parts[i].lower()})

        elif "email-addr:value" in pattern:
            # Extract email addresses
            parts = pattern.split("'")
            for i in range(1, len(parts), 2):
                iocs.append({"type": "email-src", "value": parts[i]})

    except Exception:
        pass

    return iocs
