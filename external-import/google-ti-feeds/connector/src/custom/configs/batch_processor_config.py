"""GTI batch processor configuration using the new generic batch processor system.

This module defines common utilities for batch processing GTI STIX objects
using the generic batch processor system.
"""

import logging
from datetime import datetime, timezone
from typing import Any

LOG_PREFIX = "[GenericBatchProcessor]"


def extract_stix_date_for_type(target_object_type: str) -> Any:
    """Create a date extraction function for a specific STIX object type.

    Args:
        target_object_type: The STIX object type to extract dates from

    Returns:
        A function that extracts dates from STIX objects of the specified type

    """

    def extract_stix_date(stix_object: Any) -> Any | None:
        """Extract the latest date from a STIX object for state updates.

        Only extracts dates from the specified object type to track the latest processed.
        Ignores all other object types (identity, malware, etc.).

        Args:
            stix_object: STIX object to extract date from

        Returns:
            ISO format date string with timezone information or None

        """
        object_type: str = getattr(
            stix_object,
            "type",
            (
                stix_object.get("type", "unknown")
                if hasattr(stix_object, "get")
                else "unknown"
            ),
        )
        if object_type != target_object_type:
            return None

        date_value = getattr(
            stix_object,
            "modified",
            stix_object.get("modified") if hasattr(stix_object, "get") else None,
        )
        if date_value:
            now_utc = datetime.now(timezone.utc)
            if hasattr(date_value, "replace"):
                date_with_tz = (
                    date_value.replace(tzinfo=timezone.utc)
                    if date_value.tzinfo is None
                    else date_value
                )
                if date_with_tz > now_utc:
                    return now_utc.isoformat()
                return date_value.isoformat()
            if isinstance(date_value, str):
                try:
                    parsed_date = datetime.fromisoformat(
                        date_value.replace("Z", "+00:00")
                    )
                    date_with_tz = (
                        parsed_date.replace(tzinfo=timezone.utc)
                        if parsed_date.tzinfo is None
                        else parsed_date
                    )
                    if date_with_tz > now_utc:
                        return now_utc.isoformat()
                except (ValueError, AttributeError):
                    pass
                return date_value

        return None

    return extract_stix_date


def validate_stix_object(stix_obj: Any) -> bool:
    """Validate STIX object before adding to batch.

    Args:
        stix_obj: STIX object to validate

    Returns:
        True if valid, False otherwise

    """
    return (
        hasattr(stix_obj, "id")
        and hasattr(stix_obj, "type")
        and stix_obj.id is not None
        and stix_obj.type is not None
    )


def log_batch_completion(stix_objects: list[Any], work_id: str) -> None:
    """Log successful batch completion with object type breakdown.

    Args:
        stix_objects: list of processed STIX objects
        work_id: Work ID that was created

    """
    logger = logging.getLogger(__name__)

    object_types: dict[str, int] = {}
    total_count = 0

    for obj in stix_objects:
        total_count += 1

        if total_count <= 2500:
            if hasattr(obj, "type"):
                obj_type = obj.type
            elif hasattr(obj, "get"):
                obj_type = obj.get("type", "unknown")
            else:
                obj_type = "unknown"
            object_types[obj_type] = object_types.get(obj_type, 0) + 1

    if total_count > 2500:
        type_summary = (
            ", ".join(
                [f"{obj_type}: {count}" for obj_type, count in object_types.items()]
            )
            + " (first 2500 objects)"
        )
    else:
        type_summary = ", ".join(
            [f"{obj_type}: {count}" for obj_type, count in object_types.items()]
        )

    logger.info(
        "Batch completed successfully",
        {
            "prefix": LOG_PREFIX,
            "work_id": work_id,
            "total_count": total_count,
            "type_summary": type_summary,
        },
    )
