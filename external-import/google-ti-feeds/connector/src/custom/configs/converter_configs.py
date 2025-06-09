"""GTI converter configurations using the generic converter system.

This module defines configurations for converting different types of GTI entities
to STIX format using the generic converter system.
"""

import logging
from typing import Any

from connector.src.custom.exceptions import (
    GTIActorConversionError,
    GTIDomainConversionError,
    GTIFileConversionError,
    GTIIPConversionError,
    GTIMalwareConversionError,
    GTIReportConversionError,
    GTITechniqueConversionError,
    GTIUrlConversionError,
    GTIVulnerabilityConversionError,
)
from connector.src.custom.mappers.gti_reports.gti_attack_technique_to_stix_attack_pattern import (
    GTIAttackTechniqueToSTIXAttackPattern,
)
from connector.src.custom.mappers.gti_reports.gti_domain_to_stix_domain import (
    GTIDomainToSTIXDomain,
)
from connector.src.custom.mappers.gti_reports.gti_file_to_stix_file import (
    GTIFileToSTIXFile,
)
from connector.src.custom.mappers.gti_reports.gti_ip_to_stix_ip import (
    GTIIPToSTIXIP,
)
from connector.src.custom.mappers.gti_reports.gti_malware_family_to_stix_malware import (
    GTIMalwareFamilyToSTIXMalware,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_composite import (
    GTIReportToSTIXComposite,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_identity import (
    GTIReportToSTIXIdentity,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_location import (
    GTIReportToSTIXLocation,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_report import (
    GTIReportToSTIXReport,
)
from connector.src.custom.mappers.gti_reports.gti_threat_actor_to_stix_intrusion_set import (
    GTIThreatActorToSTIXIntrusionSet,
)
from connector.src.custom.mappers.gti_reports.gti_url_to_stix_url import (
    GTIUrlToSTIXUrl,
)
from connector.src.custom.mappers.gti_reports.gti_vulnerability_to_stix_vulnerability import (
    GTIVulnerabilityToSTIXVulnerability,
)
from connector.src.custom.models.gti_reports.gti_attack_technique_model import (
    GTIAttackTechniqueData,
)
from connector.src.custom.models.gti_reports.gti_domain_model import (
    GTIDomainData,
)
from connector.src.custom.models.gti_reports.gti_file_model import (
    GTIFileData,
)
from connector.src.custom.models.gti_reports.gti_ip_addresses_model import (
    GTIIPData,
)
from connector.src.custom.models.gti_reports.gti_malware_family_model import (
    GTIMalwareFamilyData,
)
from connector.src.custom.models.gti_reports.gti_report_model import GTIReportData
from connector.src.custom.models.gti_reports.gti_threat_actor_model import (
    GTIThreatActorData,
)
from connector.src.custom.models.gti_reports.gti_url_model import (
    GTIURLData,
)
from connector.src.custom.models.gti_reports.gti_vulnerability_model import (
    GTIVulnerabilityData,
)
from connector.src.utils.converters.generic_converter_config import (
    GenericConverterConfig,
)

_current_report_context = None

LOG_PREFIX = "[GTIConverterConfigs]"


def set_report_context(report_obj: Any) -> None:
    """Set the current report context for linking."""
    global _current_report_context
    _current_report_context = report_obj


def get_report_context() -> Any:
    """Get the current report context."""
    # flake8: noqa # in used to create relationships/object_refs
    global _current_report_context
    return _current_report_context


def clear_report_context() -> None:
    """Clear the report context."""
    global _current_report_context
    _current_report_context = None


def create_report_linking_postprocessor() -> Any:
    """Create a postprocessing function that links sub-entities to their parent report.

    Returns:
        Postprocessing function that can be used in GenericConverterConfig

    """

    def postprocess_for_report_linking(stix_output: Any) -> Any:
        """Postprocess STIX output to link objects to their parent report.

        Args:
            stix_output: The converted STIX object(s)

        Returns:
            The same STIX output (unchanged)

        """
        parent_report = get_report_context()
        if not parent_report:
            return stix_output

        logger = logging.getLogger(__name__)

        try:
            object_ids = []

            if isinstance(stix_output, list):
                for obj in stix_output:
                    if hasattr(obj, "id"):
                        object_ids.append(obj.id)
            elif hasattr(stix_output, "id"):
                object_ids.append(stix_output.id)

            if object_ids:
                GTIReportToSTIXReport.add_object_refs(object_ids, parent_report)
                logger.debug(
                    f"{LOG_PREFIX} Linked {len(object_ids)} objects to report {getattr(parent_report, 'id', 'unknown')}"
                )

        except Exception as e:
            logger.warning(
                f"{LOG_PREFIX} Error in report linking postprocessor: {str(e)}"
            )

        return stix_output

    return postprocess_for_report_linking


GTI_REPORT_LOCATION_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="report_locations",
    mapper_class=GTIReportToSTIXLocation,
    output_stix_type="location",
    exception_class=GTIReportConversionError,
    display_name="report locations",
    input_model=GTIReportData,
    display_name_singular="report location",
    validate_input=True,
)

GTI_REPORT_IDENTITY_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="report_identities",
    mapper_class=GTIReportToSTIXIdentity,
    output_stix_type="identity",
    exception_class=GTIReportConversionError,
    display_name="report identities",
    input_model=GTIReportData,
    display_name_singular="report identity",
    validate_input=True,
)

GTI_REPORT_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="reports",
    mapper_class=GTIReportToSTIXComposite,
    output_stix_type="report",
    exception_class=GTIReportConversionError,
    display_name="reports",
    input_model=GTIReportData,
    display_name_singular="report",
    validate_input=True,
)

GTI_MALWARE_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="malware_families",
    mapper_class=GTIMalwareFamilyToSTIXMalware,
    output_stix_type="malware",
    exception_class=GTIMalwareConversionError,
    display_name="malware families",
    input_model=GTIMalwareFamilyData,
    display_name_singular="malware family",
    validate_input=True,
    postprocessing_function=create_report_linking_postprocessor(),
)

GTI_THREAT_ACTOR_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="threat_actors",
    mapper_class=GTIThreatActorToSTIXIntrusionSet,
    output_stix_type="intrusion-set",
    exception_class=GTIActorConversionError,
    display_name="threat actors",
    input_model=GTIThreatActorData,
    display_name_singular="threat actor",
    validate_input=True,
    postprocessing_function=create_report_linking_postprocessor(),
)

GTI_ATTACK_TECHNIQUE_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="attack_techniques",
    mapper_class=GTIAttackTechniqueToSTIXAttackPattern,
    output_stix_type="attack-pattern",
    exception_class=GTITechniqueConversionError,
    display_name="attack techniques",
    input_model=GTIAttackTechniqueData,
    display_name_singular="attack technique",
    validate_input=True,
    postprocessing_function=create_report_linking_postprocessor(),
)

GTI_VULNERABILITY_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="vulnerabilities",
    mapper_class=GTIVulnerabilityToSTIXVulnerability,
    output_stix_type="vulnerability",
    exception_class=GTIVulnerabilityConversionError,
    display_name="vulnerabilities",
    input_model=GTIVulnerabilityData,
    display_name_singular="vulnerability",
    validate_input=True,
    postprocessing_function=create_report_linking_postprocessor(),
)

GTI_DOMAIN_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="domains",
    mapper_class=GTIDomainToSTIXDomain,
    output_stix_type="domain",
    exception_class=GTIDomainConversionError,
    display_name="domains",
    input_model=GTIDomainData,
    display_name_singular="domain",
    validate_input=True,
    postprocessing_function=create_report_linking_postprocessor(),
)

GTI_FILE_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="files",
    mapper_class=GTIFileToSTIXFile,
    output_stix_type="file",
    exception_class=GTIFileConversionError,
    display_name="files",
    input_model=GTIFileData,
    display_name_singular="file",
    validate_input=True,
    postprocessing_function=create_report_linking_postprocessor(),
)

GTI_URL_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="urls",
    mapper_class=GTIUrlToSTIXUrl,
    output_stix_type="url",
    exception_class=GTIUrlConversionError,
    display_name="URLs",
    input_model=GTIURLData,
    display_name_singular="URL",
    validate_input=True,
    postprocessing_function=create_report_linking_postprocessor(),
)

GTI_IP_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="ip_addresses",
    mapper_class=GTIIPToSTIXIP,
    output_stix_type="ip_address",
    exception_class=GTIIPConversionError,
    display_name="IP addresses",
    input_model=GTIIPData,
    display_name_singular="IP address",
    validate_input=True,
    postprocessing_function=create_report_linking_postprocessor(),
)

CONVERTER_CONFIGS = {
    "reports": GTI_REPORT_CONVERTER_CONFIG,
    "report_locations": GTI_REPORT_LOCATION_CONVERTER_CONFIG,
    "report_identities": GTI_REPORT_IDENTITY_CONVERTER_CONFIG,
    "malware_families": GTI_MALWARE_CONVERTER_CONFIG,
    "threat_actors": GTI_THREAT_ACTOR_CONVERTER_CONFIG,
    "attack_techniques": GTI_ATTACK_TECHNIQUE_CONVERTER_CONFIG,
    "vulnerabilities": GTI_VULNERABILITY_CONVERTER_CONFIG,
    "domains": GTI_DOMAIN_CONVERTER_CONFIG,
    "files": GTI_FILE_CONVERTER_CONFIG,
    "urls": GTI_URL_CONVERTER_CONFIG,
    "ip_addresses": GTI_IP_CONVERTER_CONFIG,
}
