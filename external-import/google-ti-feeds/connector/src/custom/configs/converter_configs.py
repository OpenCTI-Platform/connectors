"""GTI converter configurations using the generic converter system.

This module defines configurations for converting different types of GTI entities
to STIX format using the generic converter system.
"""

import logging
from typing import Any, Optional, Protocol

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
from connector.src.custom.mappers.gti_attack_techniques.gti_attack_technique_to_stix_attack_pattern import (
    GTIAttackTechniqueToSTIXAttackPattern,
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
from connector.src.custom.mappers.gti_malwares.gti_malware_family_to_stix_identity import (
    GTIMalwareFamilyToSTIXIdentity,
)
from connector.src.custom.mappers.gti_malwares.gti_malware_family_to_stix_location import (
    GTIMalwareFamilyToSTIXLocation,
)
from connector.src.custom.mappers.gti_malwares.gti_malware_family_to_stix_malware import (
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
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_composite import (
    GTIThreatActorToSTIXComposite,
)
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_identity import (
    GTIThreatActorToSTIXIdentity,
)
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_intrusion_set import (
    GTIThreatActorToSTIXIntrusionSet,
)
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_location import (
    GTIThreatActorToSTIXLocation,
)
from connector.src.custom.mappers.gti_vulnerabilities.gti_vulnerability_to_stix_vulnerability import (
    GTIVulnerabilityToSTIXVulnerability,
)
from connector.src.custom.models.gti.gti_attack_technique_model import (
    GTIAttackTechniqueData,
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

# Global context storage
_contexts = {}

LOG_PREFIX = "[GTIConverterConfigs]"
_logger = logging.getLogger(__name__)


class RelationshipMapper(Protocol):
    """Protocol for classes that can create relationships between entities."""

    @staticmethod
    def create_relationship(source: Any, rel_type: str, target: Any) -> Any:
        """Create a relationship between source and target entities."""
        ...


def _find_report_in_output(stix_output: Any) -> Optional[Any]:
    """Find a report object in the stix_output."""
    entities = stix_output if isinstance(stix_output, list) else [stix_output]
    for obj in entities:
        if hasattr(obj, "type") and obj.type == "report":
            return obj
    return None


### Generic Context Management


def set_context(context_type: str, context_obj: Any) -> None:
    """Set the current context for linking.

    Args:
        context_type: Type of context (e.g., 'report', 'intrusion_set')
        context_obj: The context object to store

    """
    _contexts[context_type] = context_obj


def get_context(context_type: str) -> Any:
    """Get the current context.

    Args:
        context_type: Type of context to retrieve

    Returns:
        The stored context object or None if not found

    """
    return _contexts.get(context_type)


def clear_context(context_type: str) -> None:
    """Clear the context.

    Args:
        context_type: Type of context to clear

    """
    _contexts.pop(context_type, None)


def clear_all_contexts() -> None:
    """Clear all contexts."""
    _contexts.clear()


# === CORE POSTPROCESSOR FUNCTIONS ===


def add_to_refs(context_key: str, linking_method: Any) -> Any:
    """Add objects to parent's object_refs.

    Args:
        context_key: Context key to get parent from (e.g. 'report')
        linking_method: Method to call (e.g. GTIReportToSTIXReport.add_object_refs)

    """

    def postprocess(stix_output: Any) -> Any:
        parent = get_context(context_key)
        if not parent:
            return stix_output

        try:
            object_ids = []
            if isinstance(stix_output, list):
                object_ids = [obj.id for obj in stix_output if hasattr(obj, "id")]
            elif hasattr(stix_output, "id"):
                object_ids = [stix_output.id]

            if object_ids:
                linking_method(object_ids, parent)
                _logger.debug(
                    f"{LOG_PREFIX} Added {len(object_ids)} refs to {context_key}"
                )

        except Exception as e:
            _logger.warning(f"{LOG_PREFIX} Error adding refs: {str(e)}")

        return stix_output

    return postprocess


def create_relationship(
    relationship_type: str,
    source_context: str,
    mapper_class: RelationshipMapper,
    reverse: bool = False,
) -> Any:
    """Create SRO relationships.

    Args:
        relationship_type: Type like 'uses', 'targets', 'related-to'
        source_context: Context key for source entity (e.g. 'intrusion_set')
        mapper_class: Mapper with create_relationship static method
        reverse: If True, swap source and target (current entity becomes source)

    """

    def postprocess(stix_output: Any) -> Any:
        context_entity = get_context(source_context)
        if not context_entity:
            return stix_output

        entities = stix_output if isinstance(stix_output, list) else [stix_output]
        result = entities.copy()

        if not hasattr(mapper_class, "create_relationship"):
            _logger.warning(
                f"{LOG_PREFIX} Mapper {str(mapper_class)} lacks create_relationship method"
            )
            return result

        try:
            for entity in entities:
                relationship = _create_single_relationship(
                    entity, context_entity, relationship_type, mapper_class, reverse
                )
                if relationship:
                    result.append(relationship)

        except Exception as e:
            _logger.warning(
                f"{LOG_PREFIX} Error creating {relationship_type}: {str(e)}"
            )

        return result

    return postprocess


def _create_single_relationship(
    entity: Any,
    context_entity: Any,
    relationship_type: str,
    mapper_class: RelationshipMapper,
    reverse: bool,
) -> Optional[Any]:
    """Create a single relationship between two entities."""
    if not (hasattr(entity, "id") and not hasattr(entity, "relationship_type")):
        return None

    try:
        if reverse:
            rel = mapper_class.create_relationship(
                entity, relationship_type, context_entity
            )
            _logger.debug(
                f"{LOG_PREFIX} Created reverse {relationship_type}: {entity.id} → {context_entity.id}"
            )
        else:
            rel = mapper_class.create_relationship(
                context_entity, relationship_type, entity
            )
            _logger.debug(
                f"{LOG_PREFIX} Created {relationship_type}: {context_entity.id} → {entity.id}"
            )

        return rel

    except Exception as e:
        _logger.warning(
            f"{LOG_PREFIX} Failed to create {relationship_type} for {entity.id}: {str(e)}"
        )
        return None


def manage_context(operation: str, context_key: Optional[str] = None) -> Any:
    """Manage context storage.

    Args:
        operation: 'set' or 'clear' or 'clear_all'
        context_key: Key for set/clear operations

    """

    def postprocess(stix_output: Any) -> Any:
        try:
            if operation == "set" and context_key:
                entity = None
                if isinstance(stix_output, list):
                    for obj in stix_output:
                        if hasattr(obj, "type") and obj.type == context_key.replace(
                            "_", "-"
                        ):
                            entity = obj
                            break
                elif hasattr(stix_output, "type"):
                    entity = stix_output

                if entity:
                    set_context(context_key, entity)
                    _logger.debug(f"{LOG_PREFIX} Set {context_key} context")

            elif operation == "clear" and context_key:
                clear_context(context_key)
                _logger.debug(f"{LOG_PREFIX} Cleared {context_key} context")

            elif operation == "clear_all":
                clear_all_contexts()
                _logger.debug(f"{LOG_PREFIX} Cleared all contexts")

        except Exception as e:
            _logger.warning(f"{LOG_PREFIX} Error managing context: {str(e)}")

        return stix_output

    return postprocess


# === CONVENIENCE FUNCTIONS ===


def link_to_report() -> Any:
    """Add objects to report's object_refs."""
    return add_to_refs("report", GTIReportToSTIXReport.add_object_refs)


def uses_relationship(
    mapper_class: Any, source_context: str, reverse: bool = False
) -> Any:
    """Create 'uses' relationships from source context."""
    return create_relationship("uses", source_context, mapper_class, reverse)


def targets_relationship(
    mapper_class: Any, source_context: str, reverse: bool = False
) -> Any:
    """Create 'targets' relationships from source context."""
    return create_relationship("targets", source_context, mapper_class, reverse)


def related_to_relationship(
    mapper_class: Any, source_context: str, reverse: bool = False
) -> Any:
    """Create 'related-to' relationships from source context."""
    return create_relationship("related-to", source_context, mapper_class, reverse)


def exploits_relationship(
    mapper_class: Any, source_context: str, reverse: bool = False
) -> Any:
    """Create 'exploits' relationships from source context."""
    return create_relationship("exploits", source_context, mapper_class, reverse)


def context_to_report_relationship(
    source_context: str, relationship_creator: Any
) -> Any:
    """Create 'related-to' relationship from context entity to report in stix_output."""

    def postprocess(stix_output: Any) -> Any:
        entity = get_context(source_context)
        if not entity:
            return stix_output

        result = stix_output if isinstance(stix_output, list) else [stix_output]

        try:
            report = _find_report_in_output(stix_output)
            if report and hasattr(entity, "id"):
                rel = relationship_creator.create_relationship(
                    entity, "related-to", report
                )
                result.append(rel)
                _logger.debug(
                    f"{LOG_PREFIX} Created relationship: {entity.id} → {report.id}"
                )

        except Exception as e:
            _logger.warning(
                f"{LOG_PREFIX} Error creating context-to-report relationship: {str(e)}"
            )

        return result

    return postprocess


def add_context_to_report_refs(context_key: str) -> Any:
    """Add context entity to report object_refs."""

    def postprocess(stix_output: Any) -> Any:
        entity = get_context(context_key)
        if not entity or not hasattr(entity, "id"):
            return stix_output

        try:
            report = _find_report_in_output(stix_output)
            if report:
                GTIReportToSTIXReport.add_object_refs([entity.id], report)
                _logger.debug(f"{LOG_PREFIX} Added {entity.id} to report refs")

        except Exception as e:
            _logger.warning(
                f"{LOG_PREFIX} Error adding context to report refs: {str(e)}"
            )

        return stix_output

    return postprocess


def set_context_for(context_key: str) -> Any:
    """Store entity in context for later use."""
    return manage_context("set", context_key)


def clear_context_for(context_key: str) -> Any:
    """Clear specific context."""
    return manage_context("clear", context_key)


def clear_all_context() -> Any:
    """Clear all stored contexts."""
    return manage_context("clear_all")


def set_intrusion_set_context() -> Any:
    """Store intrusion set in context for later use."""
    return set_context_for("intrusion_set")


def set_malware_family_context() -> Any:
    """Store malware family in context for later use."""
    return set_context_for("malware")


def set_report_context() -> Any:
    """Store report in context for later use."""
    return set_context_for("report")


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
    postprocessing_function=link_to_report(),
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
    postprocessing_function=link_to_report(),
)

GTI_REPORT_ATTACK_TECHNIQUE_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="attack_techniques",
    mapper_class=GTIAttackTechniqueToSTIXAttackPattern,
    output_stix_type="attack-pattern",
    exception_class=GTITechniqueConversionError,
    display_name="attack techniques",
    input_model=GTIAttackTechniqueData,
    display_name_singular="attack technique",
    validate_input=True,
    postprocessing_function=link_to_report(),
)

GTI_REPORT_VULNERABILITY_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="vulnerabilities",
    mapper_class=GTIVulnerabilityToSTIXVulnerability,
    output_stix_type="vulnerability",
    exception_class=GTIVulnerabilityConversionError,
    display_name="vulnerabilities",
    input_model=GTIVulnerabilityData,
    display_name_singular="vulnerability",
    validate_input=True,
    postprocessing_function=link_to_report(),
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

### Intrusion Sets

GTI_THREAT_ACTOR_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="threat_actors",
    mapper_class=GTIThreatActorToSTIXComposite,
    output_stix_type="intrusion-set",
    exception_class=GTIActorConversionError,
    display_name="threat actors",
    input_model=GTIThreatActorData,
    display_name_singular="threat actor",
    validate_input=True,
    postprocessing_function=set_intrusion_set_context(),
)

GTI_THREAT_ACTOR_LOCATION_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="threat_locations",
    mapper_class=GTIThreatActorToSTIXLocation,
    output_stix_type="location",
    exception_class=GTIActorConversionError,
    display_name="threat actor locations",
    input_model=GTIThreatActorData,
    display_name_singular="threat actor location",
    validate_input=True,
)

GTI_THREAT_ACTOR_IDENTITY_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="threat_actor_identities",
    mapper_class=GTIThreatActorToSTIXIdentity,
    output_stix_type="identity",
    exception_class=GTIActorConversionError,
    display_name="threat actor identities",
    input_model=GTIThreatActorData,
    display_name_singular="threat actor identity",
    validate_input=True,
)

GTI_THREAT_ACTOR_MALWARE_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="malware_families",
    mapper_class=GTIMalwareFamilyToSTIXComposite,
    output_stix_type="malware",
    exception_class=GTIMalwareConversionError,
    display_name="malware families",
    input_model=GTIMalwareFamilyData,
    display_name_singular="malware family",
    validate_input=True,
    postprocessing_function=uses_relationship(
        GTIMalwareFamilyToSTIXMalware, "intrusion_set"
    ),
)


def entity_to_report(
    context_key: str, entity_type: str, relationship_creator: Any
) -> Any:
    """Create relationship + add ref from entity to report (mutualized function)."""

    def postprocess(stix_output: Any) -> Any:
        result = context_to_report_relationship(context_key, relationship_creator)(
            stix_output
        )

        result = add_context_to_report_refs(context_key)(result)

        return result

    return postprocess


def intrusion_set_to_report() -> Any:
    """Create relationship + add ref from intrusion set to report."""

    def postprocess(stix_output: Any) -> Any:
        result = context_to_report_relationship(
            "intrusion_set", GTIThreatActorToSTIXIntrusionSet
        )(stix_output)

        result = add_context_to_report_refs("intrusion_set")(result)

        return result

    return postprocess


def malware_family_to_report() -> Any:
    """Create relationship + add ref from malware family to report."""

    def postprocess(stix_output: Any) -> Any:
        result = context_to_report_relationship(
            "malware", GTIMalwareFamilyToSTIXMalware
        )(stix_output)

        result = add_context_to_report_refs("malware")(result)

        return result

    return postprocess


GTI_THREAT_ACTOR_REPORT_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="reports",
    mapper_class=GTIReportToSTIXComposite,
    output_stix_type="report",
    exception_class=GTIReportConversionError,
    display_name="reports",
    input_model=GTIReportData,
    display_name_singular="report",
    validate_input=True,
    postprocessing_function=intrusion_set_to_report(),
)

GTI_THREAT_ACTOR_ATTACK_TECHNIQUE_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="attack_techniques",
    mapper_class=GTIAttackTechniqueToSTIXAttackPattern,
    output_stix_type="attack-pattern",
    exception_class=GTITechniqueConversionError,
    display_name="attack techniques",
    input_model=GTIAttackTechniqueData,
    display_name_singular="attack technique",
    validate_input=True,
    postprocessing_function=uses_relationship(
        GTIAttackTechniqueToSTIXAttackPattern, "intrusion_set"
    ),
)

GTI_THREAT_ACTOR_VULNERABILITY_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="vulnerabilities",
    mapper_class=GTIVulnerabilityToSTIXVulnerability,
    output_stix_type="vulnerability",
    exception_class=GTIVulnerabilityConversionError,
    display_name="vulnerabilities",
    input_model=GTIVulnerabilityData,
    display_name_singular="vulnerability",
    validate_input=True,
    postprocessing_function=targets_relationship(
        GTIVulnerabilityToSTIXVulnerability, "intrusion_set"
    ),
)

GTI_THREAT_ACTOR_DOMAIN_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="domains",
    mapper_class=GTIDomainToSTIXDomain,
    output_stix_type="domain",
    exception_class=GTIDomainConversionError,
    display_name="domains",
    input_model=GTIDomainData,
    display_name_singular="domain",
    validate_input=True,
    postprocessing_function=related_to_relationship(
        GTIDomainToSTIXDomain, "intrusion_set"
    ),
)

GTI_THREAT_ACTOR_FILE_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="files",
    mapper_class=GTIFileToSTIXFile,
    output_stix_type="file",
    exception_class=GTIFileConversionError,
    display_name="files",
    input_model=GTIFileData,
    display_name_singular="file",
    validate_input=True,
    postprocessing_function=related_to_relationship(GTIFileToSTIXFile, "intrusion_set"),
)

GTI_THREAT_ACTOR_URL_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="urls",
    mapper_class=GTIUrlToSTIXUrl,
    output_stix_type="url",
    exception_class=GTIUrlConversionError,
    display_name="URLs",
    input_model=GTIURLData,
    display_name_singular="URL",
    validate_input=True,
    postprocessing_function=related_to_relationship(GTIUrlToSTIXUrl, "intrusion_set"),
)

GTI_THREAT_ACTOR_IP_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="ip_addresses",
    mapper_class=GTIIPToSTIXIP,
    output_stix_type="ip_address",
    exception_class=GTIIPConversionError,
    display_name="IP addresses",
    input_model=GTIIPData,
    display_name_singular="IP address",
    validate_input=True,
    postprocessing_function=related_to_relationship(GTIIPToSTIXIP, "intrusion_set"),
)

GTI_MALWARE_FAMILY_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="malware_families",
    mapper_class=GTIMalwareFamilyToSTIXComposite,
    output_stix_type="malware-family",
    exception_class=GTIMalwareConversionError,
    display_name="Malware Families",
    input_model=GTIMalwareFamilyData,
    display_name_singular="malware family",
    validate_input=True,
    postprocessing_function=set_malware_family_context(),
)

GTI_MALWARE_FAMILY_LOCATION_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="malware_family_locations",
    mapper_class=GTIMalwareFamilyToSTIXLocation,
    output_stix_type="location",
    exception_class=GTIMalwareConversionError,
    display_name="malware family locations",
    input_model=GTIMalwareFamilyData,
    display_name_singular="malware family location",
    validate_input=True,
)

GTI_MALWARE_FAMILY_IDENTITY_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="malware_family_identities",
    mapper_class=GTIMalwareFamilyToSTIXIdentity,
    output_stix_type="identity",
    exception_class=GTIMalwareConversionError,
    display_name="malware family identities",
    input_model=GTIMalwareFamilyData,
    display_name_singular="malware family identity",
    validate_input=True,
)

GTI_MALWARE_FAMILY_REPORT_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="reports",
    mapper_class=GTIReportToSTIXComposite,
    output_stix_type="report",
    exception_class=GTIReportConversionError,
    display_name="reports",
    input_model=GTIReportData,
    display_name_singular="report",
    validate_input=True,
    postprocessing_function=malware_family_to_report(),
)

GTI_MALWARE_FAMILY_THREAT_ACTOR_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="threat_actors",
    mapper_class=GTIThreatActorToSTIXComposite,
    output_stix_type="intrusion-set",
    exception_class=GTIActorConversionError,
    display_name="threat actors",
    input_model=GTIThreatActorData,
    display_name_singular="threat actor",
    validate_input=True,
    postprocessing_function=uses_relationship(
        mapper_class=GTIThreatActorToSTIXIntrusionSet,
        source_context="malware",
        reverse=True,
    ),
)

GTI_MALWARE_FAMILY_ATTACK_TECHNIQUE_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="attack_techniques",
    mapper_class=GTIAttackTechniqueToSTIXAttackPattern,
    output_stix_type="attack-pattern",
    exception_class=GTITechniqueConversionError,
    display_name="attack techniques",
    input_model=GTIAttackTechniqueData,
    display_name_singular="attack technique",
    validate_input=True,
    postprocessing_function=uses_relationship(
        mapper_class=GTIAttackTechniqueToSTIXAttackPattern,
        source_context="malware",
    ),
)

GTI_MALWARE_FAMILY_VULNERABILITY_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="vulnerabilities",
    mapper_class=GTIVulnerabilityToSTIXVulnerability,
    output_stix_type="vulnerability",
    exception_class=GTIVulnerabilityConversionError,
    display_name="vulnerabilities",
    input_model=GTIVulnerabilityData,
    display_name_singular="vulnerability",
    validate_input=True,
    postprocessing_function=targets_relationship(
        mapper_class=GTIVulnerabilityToSTIXVulnerability,
        source_context="malware",
    ),
)

GTI_MALWARE_FAMILY_DOMAIN_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="domains",
    mapper_class=GTIDomainToSTIXDomain,
    output_stix_type="domain",
    exception_class=GTIDomainConversionError,
    display_name="domains",
    input_model=GTIDomainData,
    display_name_singular="domain",
    validate_input=True,
    postprocessing_function=related_to_relationship(
        mapper_class=GTIDomainToSTIXDomain, source_context="malware"
    ),
)

GTI_MALWARE_FAMILY_FILE_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="files",
    mapper_class=GTIFileToSTIXFile,
    output_stix_type="file",
    exception_class=GTIFileConversionError,
    display_name="files",
    input_model=GTIFileData,
    display_name_singular="file",
    validate_input=True,
    postprocessing_function=related_to_relationship(
        mapper_class=GTIFileToSTIXFile, source_context="malware"
    ),
)

GTI_MALWARE_FAMILY_URL_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="urls",
    mapper_class=GTIUrlToSTIXUrl,
    output_stix_type="url",
    exception_class=GTIUrlConversionError,
    display_name="URLs",
    input_model=GTIURLData,
    display_name_singular="URL",
    validate_input=True,
    postprocessing_function=related_to_relationship(
        mapper_class=GTIUrlToSTIXUrl, source_context="malware"
    ),
)

GTI_MALWARE_FAMILY_IP_CONVERTER_CONFIG = GenericConverterConfig(
    entity_type="ip_addresses",
    mapper_class=GTIIPToSTIXIP,
    output_stix_type="ip_address",
    exception_class=GTIIPConversionError,
    display_name="IP addresses",
    input_model=GTIIPData,
    display_name_singular="IP address",
    validate_input=True,
    postprocessing_function=related_to_relationship(
        mapper_class=GTIIPToSTIXIP, source_context="malware"
    ),
)


### Configs
CONVERTER_CONFIGS = {
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
    "threat_actor": GTI_THREAT_ACTOR_CONVERTER_CONFIG,
    "threat_actor_locations": GTI_THREAT_ACTOR_LOCATION_CONVERTER_CONFIG,
    "threat_actor_identities": GTI_THREAT_ACTOR_IDENTITY_CONVERTER_CONFIG,
    "threat_actor_malware_families": GTI_THREAT_ACTOR_MALWARE_CONVERTER_CONFIG,
    "threat_actor_reports": GTI_THREAT_ACTOR_REPORT_CONVERTER_CONFIG,
    "threat_actor_attack_techniques": GTI_THREAT_ACTOR_ATTACK_TECHNIQUE_CONVERTER_CONFIG,
    "threat_actor_vulnerabilities": GTI_THREAT_ACTOR_VULNERABILITY_CONVERTER_CONFIG,
    "threat_actor_domains": GTI_THREAT_ACTOR_DOMAIN_CONVERTER_CONFIG,
    "threat_actor_files": GTI_THREAT_ACTOR_FILE_CONVERTER_CONFIG,
    "threat_actor_urls": GTI_THREAT_ACTOR_URL_CONVERTER_CONFIG,
    "threat_actor_ip_addresses": GTI_THREAT_ACTOR_IP_CONVERTER_CONFIG,
    "malware_family": GTI_MALWARE_FAMILY_CONVERTER_CONFIG,
    "malware_family_locations": GTI_MALWARE_FAMILY_LOCATION_CONVERTER_CONFIG,
    "malware_family_identities": GTI_MALWARE_FAMILY_IDENTITY_CONVERTER_CONFIG,
    "malware_family_reports": GTI_MALWARE_FAMILY_REPORT_CONVERTER_CONFIG,
    "malware_family_threat_actors": GTI_MALWARE_FAMILY_THREAT_ACTOR_CONVERTER_CONFIG,
    "malware_family_attack_techniques": GTI_MALWARE_FAMILY_ATTACK_TECHNIQUE_CONVERTER_CONFIG,
    "malware_family_vulnerabilities": GTI_MALWARE_FAMILY_VULNERABILITY_CONVERTER_CONFIG,
    "malware_family_domains": GTI_MALWARE_FAMILY_DOMAIN_CONVERTER_CONFIG,
    "malware_family_files": GTI_MALWARE_FAMILY_FILE_CONVERTER_CONFIG,
    "malware_family_urls": GTI_MALWARE_FAMILY_URL_CONVERTER_CONFIG,
    "malware_family_ip_addresses": GTI_MALWARE_FAMILY_IP_CONVERTER_CONFIG,
}
