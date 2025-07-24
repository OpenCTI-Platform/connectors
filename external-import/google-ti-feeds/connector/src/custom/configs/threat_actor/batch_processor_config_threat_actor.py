"""GTI batch processor configuration for threat actors.

This module defines configuration for batch processing GTI threat actor STIX objects
using the generic batch processor system.
"""

from typing import Any, Optional

from connector.src.custom.configs.batch_processor_config import (
    extract_stix_date_for_type,
    log_batch_completion,
    validate_stix_object,
)
from connector.src.custom.exceptions import GTIWorkProcessingError
from connector.src.utils.batch_processors.generic_batch_processor_config import (
    GenericBatchProcessorConfig,
)


def threat_actor_extract_stix_date(stix_object: Any) -> Optional[Any]:
    """Extract the latest date from a STIX object for state updates.

    Only extracts dates from intrusion-set objects to track the latest processed.
    Ignores all other object types (identity, malware, etc.).

    Args:
        stix_object: STIX object to extract date from

    Returns:
        ISO format date string with timezone information or None

    """
    return extract_stix_date_for_type("intrusion-set")(stix_object)


THREAT_ACTOR_BATCH_PROCESSOR_CONFIG = GenericBatchProcessorConfig(
    batch_size=9999,
    work_name_template="Google Threat Intel - Batch #{batch_num} (~ 0/0 threat actors)",
    state_key="threat_actor_next_cursor_start_date",
    entity_type="stix_objects",
    display_name="STIX objects",
    exception_class=GTIWorkProcessingError,
    display_name_singular="STIX object",
    auto_process=False,
    date_extraction_function=threat_actor_extract_stix_date,
    postprocessing_function=log_batch_completion,
    validation_function=validate_stix_object,
    empty_batch_behavior="update_state",
)
