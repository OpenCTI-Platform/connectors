"""Exception classes for STIX conversion errors."""

from connector.src.custom.exceptions.convert_errors.gti_actor_conversion_error import (
    GTIActorConversionError,
)
from connector.src.custom.exceptions.convert_errors.gti_entity_conversion_error import (
    GTIEntityConversionError,
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
]
