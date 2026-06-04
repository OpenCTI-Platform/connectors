"""GTI batch processor configuration for software toolkits.

This module defines configuration for batch processing GTI software toolkit STIX objects
using the generic batch processor system.
"""

from typing import Any

from connector.src.custom.configs.batch_processor_config import (
    extract_stix_date_for_type,
    log_batch_completion,
    validate_stix_object,
)
from connector.src.custom.exceptions import GTIWorkProcessingError
from connector.src.utils.batch_processors.generic_batch_processor_config import (
    GenericBatchProcessorConfig,
)


def software_toolkit_extract_stix_date(stix_object: Any) -> Any | None:
    """Extract the latest date from a STIX object for state updates.

    Only extracts dates from tool objects to track the latest processed software toolkit.
    Ignores all other object types (identity, malware, etc.).

    Args:
        stix_object: STIX object to extract date from

    Returns:
        ISO format date string with timezone information or None

    """
    return extract_stix_date_for_type("tool")(stix_object)


SOFTWARE_TOOLKIT_BATCH_PROCESSOR_CONFIG = GenericBatchProcessorConfig(
    batch_size=9999,
    work_name_template="Google Threat Intel - Batch #{batch_num} (~ 0/0 software toolkits)",
    state_key="software_toolkit_next_cursor_start_date",
    entity_type="stix_objects",
    display_name="STIX objects",
    exception_class=GTIWorkProcessingError,
    display_name_singular="STIX object",
    auto_process=False,
    date_extraction_function=software_toolkit_extract_stix_date,
    postprocessing_function=log_batch_completion,
    validation_function=validate_stix_object,
)
