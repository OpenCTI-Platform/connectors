"""Exception classes for data fetching errors."""

from connector.src.custom.exceptions.fetch_errors.gti_actor_fetch_error import (
    GTIActorFetchError,
)
from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError
from connector.src.custom.exceptions.fetch_errors.gti_domain_fetch_error import (
    GTIDomainFetchError,
)
from connector.src.custom.exceptions.fetch_errors.gti_file_fetch_error import (
    GTIFileFetchError,
)
from connector.src.custom.exceptions.fetch_errors.gti_ip_fetch_error import (
    GTIIPFetchError,
)
from connector.src.custom.exceptions.fetch_errors.gti_malware_fetch_error import (
    GTIMalwareFetchError,
)
from connector.src.custom.exceptions.fetch_errors.gti_pagination_error import (
    GTIPaginationError,
)
from connector.src.custom.exceptions.fetch_errors.gti_parsing_error import (
    GTIParsingError,
)
from connector.src.custom.exceptions.fetch_errors.gti_relationship_fetch_error import (
    GTIRelationshipFetchError,
)
from connector.src.custom.exceptions.fetch_errors.gti_report_fetch_error import (
    GTIReportFetchError,
)
from connector.src.custom.exceptions.fetch_errors.gti_technique_fetch_error import (
    GTITechniqueFetchError,
)
from connector.src.custom.exceptions.fetch_errors.gti_url_fetch_error import (
    GTIUrlFetchError,
)
from connector.src.custom.exceptions.fetch_errors.gti_vulnerability_fetch_error import (
    GTIVulnerabilityFetchError,
)

__all__ = [
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
    "GTIUrlFetchError",
    "GTIIPFetchError",
]
