"""Exception classes for the Google Threat Intelligence Feed connector."""

from connector.src.custom.exceptions.connector_errors import (
    GTIApiClientError,
    GTIAsyncError,
    GTIPartialDataProcessingError,
    GTIStateManagementError,
    GTIWorkProcessingError,
)
from connector.src.custom.exceptions.convert_errors import (
    GTIActorConversionError,
    GTIEntityConversionError,
    GTIMalwareConversionError,
    GTIMarkingCreationError,
    GTIOrganizationCreationError,
    GTIReferenceError,
    GTIReportConversionError,
    GTITechniqueConversionError,
    GTIVulnerabilityConversionError,
)
from connector.src.custom.exceptions.fetch_errors import (
    GTIActorFetchError,
    GTIApiError,
    GTIMalwareFetchError,
    GTIPaginationError,
    GTIParsingError,
    GTIRelationshipFetchError,
    GTIReportFetchError,
    GTITechniqueFetchError,
    GTIVulnerabilityFetchError,
)
from connector.src.custom.exceptions.gti_base_error import GTIBaseError
from connector.src.custom.exceptions.gti_configuration_error import (
    GTIConfigurationError,
)
from connector.src.custom.exceptions.gti_converting_error import GTIConvertingError
from connector.src.custom.exceptions.gti_fetching_error import GTIFetchingError

__all__ = [
    "GTIBaseError",
    "GTIConfigurationError",
    "GTIConvertingError",
    "GTIFetchingError",
    "GTIEntityConversionError",
    "GTIOrganizationCreationError",
    "GTIMarkingCreationError",
    "GTIReferenceError",
    "GTIReportConversionError",
    "GTIMalwareConversionError",
    "GTIActorConversionError",
    "GTITechniqueConversionError",
    "GTIVulnerabilityConversionError",
    "GTIApiError",
    "GTIPaginationError",
    "GTIParsingError",
    "GTIReportFetchError",
    "GTIMalwareFetchError",
    "GTIActorFetchError",
    "GTITechniqueFetchError",
    "GTIVulnerabilityFetchError",
    "GTIRelationshipFetchError",
    "GTIWorkProcessingError",
    "GTIAsyncError",
    "GTIStateManagementError",
    "GTIPartialDataProcessingError",
    "GTIApiClientError",
]
