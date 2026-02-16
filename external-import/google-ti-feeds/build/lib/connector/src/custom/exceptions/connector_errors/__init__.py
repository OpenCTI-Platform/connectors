"""Exception classes for connector processing errors."""

from connector.src.custom.exceptions.connector_errors.gti_api_client_error import (
    GTIApiClientError,
)
from connector.src.custom.exceptions.connector_errors.gti_async_error import (
    GTIAsyncError,
)
from connector.src.custom.exceptions.connector_errors.gti_partial_data_processing_error import (
    GTIPartialDataProcessingError,
)
from connector.src.custom.exceptions.connector_errors.gti_state_management_error import (
    GTIStateManagementError,
)
from connector.src.custom.exceptions.connector_errors.gti_work_processing_error import (
    GTIWorkProcessingError,
)

__all__ = [
    "GTIWorkProcessingError",
    "GTIAsyncError",
    "GTIStateManagementError",
    "GTIPartialDataProcessingError",
    "GTIApiClientError",
]
