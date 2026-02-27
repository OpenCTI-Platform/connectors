"""GTI converter configurations for reports.

This module defines configurations for converting GTI report entities
to STIX format using the generic converter system.
"""

from connector.src.custom.configs.converter_config_common import (
    link_to_report,
    set_report_context,
)
from connector.src.custom.exceptions import (
    GTIActorConversionError,
    GTICampaignConversionError,
    GTIDomainConversionError,
    GTIFileConversionError,
    GTIIPConversionError,
    GTIMalwareConversionError,
    GTIReportConversionError,
    GTITechniqueConversionError,
    GTIUrlConversionError,
    GTIVulnerabilityConversionError,
)
from connector.src.custom.mappers.gti_attack_techniques.gti_attack_technique_ids_to_stix_attack_patterns import (
    GTIAttackTechniqueIDsToSTIXAttackPatterns,
)
from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_composite import (
    GTICampaignToSTIXComposite,
)
from connector.src.custom.mappers.gti_iocs.gti_domain_to_stix_domain import (
    GTIDomainToSTIXDomain,
)
from connector.src.custom.mappers.gti_iocs.gti_file_to_stix_file import (
    GTIFileToSTIXFile,
)
from connector.src.custom.mappers.gti_iocs.gti_ip_to_stix_ip import (
    GTIIPToSTIXIP,
)
from connector.src.custom.mappers.gti_iocs.gti_url_to_stix_url import (
    GTIUrlToSTIXUrl,
)
from connector.src.custom.mappers.gti_malwares.gti_malware_family_to_stix_composite import (
    GTIMalwareFamilyToSTIXComposite,
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
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_composite import (
    GTIThreatActorToSTIXComposite,
)
from connector.src.custom.mappers.gti_vulnerabilities.gti_vulnerability_to_stix_composite import (
    GTIVulnerabilityToSTIXComposite,
)
from connector.src.custom.models.gti.gti_attack_technique_id_model import (
    GTIAttackTechniqueIDData,
)
from connector.src.custom.models.gti.gti_campaign_model import (
    GTICampaignData,
)
from connector.src.custom.models.gti.gti_domain_model import (
    GTIDomainData,
)
from connector.src.custom.models.gti.gti_file_model import (
    GTIFileData,
)
from connector.src.custom.models.gti.gti_ip_addresses_model import (
    GTIIPData,
)
from connector.src.custom.models.gti.gti_malware_family_model import (
    GTIMalwareFamilyData,
)
from connector.src.custom.models.gti.gti_report_model import GTIReportData
from connector.src.custom.models.gti.gti_threat_actor_model import (
    GTIThreatActorData,
)
from connector.src.custom.models.gti.gti_url_model import (
    GTIURLData,
)
from connector.src.custom.models.gti.gti_vulnerability_model import (
    GTIVulnerabilityData,
)
from connector.src.utils.converters.generic_converter_config import (
    GenericConverterConfig,
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
    postprocessing_function=set_report_context(),
)

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

GTI_REPORT_MALWARE_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="malware_families",
    mapper_class=GTIMalwareFamilyToSTIXComposite,
    output_stix_type="malware",
    exception_class=GTIMalwareConversionError,
    display_name="malware families",
    input_model=GTIMalwareFamilyData,
    display_name_singular="malware family",
    validate_input=True,
    postprocessing_function=link_to_report(["malware"]),
)

GTI_REPORT_THREAT_ACTOR_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="threat_actors",
    mapper_class=GTIThreatActorToSTIXComposite,
    output_stix_type="intrusion-set",
    exception_class=GTIActorConversionError,
    display_name="threat actors",
    input_model=GTIThreatActorData,
    display_name_singular="threat actor",
    validate_input=True,
    postprocessing_function=link_to_report(["intrusion-set"]),
)

GTI_REPORT_ATTACK_TECHNIQUE_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="attack_techniques",
    mapper_class=GTIAttackTechniqueIDsToSTIXAttackPatterns,
    output_stix_type="attack-pattern",
    exception_class=GTITechniqueConversionError,
    display_name="attack techniques",
    input_model=GTIAttackTechniqueIDData,
    display_name_singular="attack technique",
    validate_input=True,
    postprocessing_function=link_to_report(),
)

GTI_REPORT_VULNERABILITY_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="vulnerabilities",
    mapper_class=GTIVulnerabilityToSTIXComposite,
    output_stix_type="vulnerability",
    exception_class=GTIVulnerabilityConversionError,
    display_name="vulnerabilities",
    input_model=GTIVulnerabilityData,
    display_name_singular="vulnerability",
    validate_input=True,
    postprocessing_function=link_to_report(["vulnerability"]),
)

GTI_REPORT_DOMAIN_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="domains",
    mapper_class=GTIDomainToSTIXDomain,
    output_stix_type="domain",
    exception_class=GTIDomainConversionError,
    display_name="domains",
    input_model=GTIDomainData,
    display_name_singular="domain",
    validate_input=True,
    postprocessing_function=link_to_report(),
)

GTI_REPORT_FILE_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="files",
    mapper_class=GTIFileToSTIXFile,
    output_stix_type="file",
    exception_class=GTIFileConversionError,
    display_name="files",
    input_model=GTIFileData,
    display_name_singular="file",
    validate_input=True,
    postprocessing_function=link_to_report(),
)

GTI_REPORT_URL_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="urls",
    mapper_class=GTIUrlToSTIXUrl,
    output_stix_type="url",
    exception_class=GTIUrlConversionError,
    display_name="URLs",
    input_model=GTIURLData,
    display_name_singular="URL",
    validate_input=True,
    postprocessing_function=link_to_report(),
)

GTI_REPORT_IP_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="ip_addresses",
    mapper_class=GTIIPToSTIXIP,
    output_stix_type="ip_address",
    exception_class=GTIIPConversionError,
    display_name="IP addresses",
    input_model=GTIIPData,
    display_name_singular="IP address",
    validate_input=True,
    postprocessing_function=link_to_report(),
)

GTI_REPORT_CAMPAIGN_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="campaigns",
    mapper_class=GTICampaignToSTIXComposite,
    output_stix_type="campaign",
    exception_class=GTICampaignConversionError,
    display_name="Campaigns",
    input_model=GTICampaignData,
    display_name_singular="Campaign",
    validate_input=True,
    postprocessing_function=link_to_report(["campaign"]),
)

REPORT_CONVERTER_CONFIGS = {
    "reports": GTI_REPORT_CONVERTER_CONFIG,
    "report_locations": GTI_REPORT_LOCATION_CONVERTER_CONFIG,
    "report_identities": GTI_REPORT_IDENTITY_CONVERTER_CONFIG,
    "report_malware_families": GTI_REPORT_MALWARE_CONVERTER_CONFIG,
    "report_threat_actors": GTI_REPORT_THREAT_ACTOR_CONVERTER_CONFIG,
    "report_attack_techniques": GTI_REPORT_ATTACK_TECHNIQUE_CONVERTER_CONFIG,
    "report_vulnerabilities": GTI_REPORT_VULNERABILITY_CONVERTER_CONFIG,
    "report_domains": GTI_REPORT_DOMAIN_CONVERTER_CONFIG,
    "report_files": GTI_REPORT_FILE_CONVERTER_CONFIG,
    "report_urls": GTI_REPORT_URL_CONVERTER_CONFIG,
    "report_ip_addresses": GTI_REPORT_IP_CONVERTER_CONFIG,
    "report_campaigns": GTI_REPORT_CAMPAIGN_CONVERTER_CONFIG,
}
