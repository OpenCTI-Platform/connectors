"""Exception classes for STIX conversion errors."""

from connector.src.custom.exceptions.convert_errors.gti_actor_conversion_error import (
    GTIActorConversionError,
)
from connector.src.custom.exceptions.convert_errors.gti_domain_conversion_error import (
    GTIDomainConversionError,
)
from connector.src.custom.exceptions.convert_errors.gti_entity_conversion_error import (
    GTIEntityConversionError,
)
from connector.src.custom.exceptions.convert_errors.gti_file_conversion_error import (
    GTIFileConversionError,
)
from connector.src.custom.exceptions.convert_errors.gti_ip_conversion_error import (
    GTIIPConversionError,
)
from connector.src.custom.exceptions.convert_errors.gti_malware_conversion_error import (
    GTIMalwareConversionError,
)
from connector.src.custom.exceptions.convert_errors.gti_marking_creation_error import (
    GTIMarkingCreationError,
)
from connector.src.custom.exceptions.convert_errors.gti_organization_creation_error import (
    GTIOrganizationCreationError,
)
from connector.src.custom.exceptions.convert_errors.gti_reference_error import (
    GTIReferenceError,
)
from connector.src.custom.exceptions.convert_errors.gti_report_conversion_error import (
    GTIReportConversionError,
)
from connector.src.custom.exceptions.convert_errors.gti_technique_conversion_error import (
    GTITechniqueConversionError,
)
from connector.src.custom.exceptions.convert_errors.gti_url_conversion_error import (
    GTIUrlConversionError,
)
from connector.src.custom.exceptions.convert_errors.gti_vulnerability_conversion_error import (
    GTIVulnerabilityConversionError,
)

__all__ = [
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
    "GTIUrlConversionError",
    "GTIIPConversionError",
]
