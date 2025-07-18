"""GTI batch processor configuration using the new generic batch processor system.

This module defines configuration for batch processing GTI STIX objects
using the generic batch processor system.
"""

from datetime import datetime, timezone
from typing import Any, List, Optional

from connector.src.custom.exceptions import GTIWorkProcessingError
from connector.src.utils.batch_processors.generic_batch_processor_config import (
    GenericBatchProcessorConfig,
)

LOG_PREFIX = "[GenericBatchProcessor]"


def extract_stix_date(stix_object: Any) -> Optional[Any]:
    """Extract the latest date from a STIX object for state updates.

    Only extracts dates from report objects to track the latest processed report.
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
    if object_type != "report":
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
                parsed_date = datetime.fromisoformat(date_value.replace("Z", "+00:00"))
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


def log_batch_completion(stix_objects: List[Any], work_id: str) -> None:
    """Log successful batch completion with object type breakdown.

    Args:
        stix_objects: List of processed STIX objects
        work_id: Work ID that was created

    """
    import logging

    logger = logging.getLogger(__name__)

    object_types: dict[str, int] = {}
    for obj in stix_objects:
        if hasattr(obj, "type"):
            obj_type = obj.type
        elif hasattr(obj, "get"):
            obj_type = obj.get("type", "unknown")
        else:
            obj_type = "unknown"
        object_types[obj_type] = object_types.get(obj_type, 0) + 1

    type_summary = ", ".join(
        [f"{obj_type}: {count}" for obj_type, count in object_types.items()]
    )

    logger.info(
        f"{LOG_PREFIX} Batch {work_id} completed successfully: {len(stix_objects)} objects ({type_summary})"
    )


BATCH_PROCESSOR_CONFIG = GenericBatchProcessorConfig(
    batch_size=500,
    work_name_template="Google Threat Intel - Batch #{batch_num} (~ 0/0 reports)",
    state_key="next_cursor_start_date",
    entity_type="stix_objects",
    display_name="STIX objects",
    exception_class=GTIWorkProcessingError,
    display_name_singular="STIX object",
    auto_process=True,
    date_extraction_function=extract_stix_date,
    postprocessing_function=log_batch_completion,
    validation_function=validate_stix_object,
    empty_batch_behavior="update_state",
)
