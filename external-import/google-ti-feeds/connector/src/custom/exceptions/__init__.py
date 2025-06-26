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
    GTIDomainConversionError,
    GTIEntityConversionError,
    GTIFileConversionError,
    GTIIPConversionError,
    GTIMalwareConversionError,
    GTIMarkingCreationError,
    GTIOrganizationCreationError,
    GTIReferenceError,
    GTIReportConversionError,
    GTITechniqueConversionError,
    GTIUrlConversionError,
    GTIVulnerabilityConversionError,
)
from connector.src.custom.exceptions.fetch_errors import (
    GTIActorFetchError,
    GTIApiError,
    GTIDomainFetchError,
    GTIFileFetchError,
    GTIIPFetchError,
    GTIMalwareFetchError,
    GTIPaginationError,
    GTIParsingError,
    GTIRelationshipFetchError,
    GTIReportFetchError,
    GTITechniqueFetchError,
    GTIUrlFetchError,
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
    "GTIDomainConversionError",
    "GTIFileConversionError",
    "GTIIPConversionError",
    "GTIUrlConversionError",
    "GTIApiError",
    "GTIPaginationError",
    "GTIParsingError",
    "GTIReportFetchError",
    "GTIMalwareFetchError",
    "GTIActorFetchError",
    "GTITechniqueFetchError",
    "GTIVulnerabilityFetchError",
    "GTIRelationshipFetchError",
    "GTIDomainFetchError",
    "GTIFileFetchError",
    "GTIIPFetchError",
    "GTIUrlFetchError",
    "GTIWorkProcessingError",
    "GTIAsyncError",
    "GTIStateManagementError",
    "GTIPartialDataProcessingError",
    "GTIApiClientError",
]
