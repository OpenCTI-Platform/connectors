"""GTI batch processor configuration for indicators."""

from connector.src.custom.configs.batch_processor_config import (
    log_batch_completion,
    validate_stix_object,
)
from connector.src.custom.exceptions import GTIWorkProcessingError
from connector.src.utils.batch_processors.generic_batch_processor_config import (
    GenericBatchProcessorConfig,
)

INDICATOR_BATCH_PROCESSOR_CONFIG = GenericBatchProcessorConfig(
    batch_size=9999,
    work_name_template="Google Threat Intel - Batch #{batch_num} (IOC indicators)",
    state_key="indicator_last_package_id",
    entity_type="stix_objects",
    display_name="STIX objects",
    exception_class=GTIWorkProcessingError,
    display_name_singular="STIX object",
    auto_process=False,
    date_extraction_function=lambda x: None,
    postprocessing_function=log_batch_completion,
    validation_function=validate_stix_object,
)
