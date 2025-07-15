"""GTI converter common utilities and helper functions.

This module defines common utilities and helper functions for converting different types of GTI entities
to STIX format using the generic converter system.
"""

import logging
from typing import Any, Optional, Protocol

from connector.src.custom.mappers.gti_reports.gti_report_to_stix_report import (
    GTIReportToSTIXReport,
)

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
    from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_intrusion_set import (
        GTIThreatActorToSTIXIntrusionSet,
    )

    def postprocess(stix_output: Any) -> Any:
        result = context_to_report_relationship(
            "intrusion_set", GTIThreatActorToSTIXIntrusionSet
        )(stix_output)

        result = add_context_to_report_refs("intrusion_set")(result)

        return result

    return postprocess


def malware_family_to_report() -> Any:
    """Create relationship + add ref from malware family to report."""
    from connector.src.custom.mappers.gti_malwares.gti_malware_family_to_stix_malware import (
        GTIMalwareFamilyToSTIXMalware,
    )

    def postprocess(stix_output: Any) -> Any:
        result = context_to_report_relationship(
            "malware", GTIMalwareFamilyToSTIXMalware
        )(stix_output)

        result = add_context_to_report_refs("malware")(result)

        return result

    return postprocess
