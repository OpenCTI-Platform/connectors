"""GTI converter common utilities and helper functions.

This module defines common utilities and helper functions for converting different types of GTI entities
to STIX format using the generic converter system.
"""

import logging
from typing import Any, Protocol

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


def _find_report_in_output(stix_output: Any) -> Any | None:
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


def add_to_refs(
    context_key: str,
    linking_method: Any,
    entity_type_filter: list[str] | None = None,
) -> Any:
    """Add objects to parent's object_refs.

    Args:
        context_key: Context key to get parent from (e.g. 'report')
        linking_method: Method to call (e.g. GTIReportToSTIXReport.add_object_refs)
        entity_type_filter: Optional list of STIX types to filter for (e.g. ['intrusion-set', 'malware'])

    """

    def postprocess(stix_output: Any) -> Any:
        parent = get_context(context_key)
        if not parent:
            return stix_output

        try:
            object_ids = []
            if isinstance(stix_output, list):
                if entity_type_filter:
                    filtered_objects = [
                        obj
                        for obj in stix_output
                        if hasattr(obj, "type")
                        and obj.type in entity_type_filter
                        and hasattr(obj, "id")
                    ]
                    object_ids = [obj.id for obj in filtered_objects]
                else:
                    object_ids = [obj.id for obj in stix_output if hasattr(obj, "id")]
            elif hasattr(stix_output, "id"):
                if not entity_type_filter or (
                    hasattr(stix_output, "type")
                    and stix_output.type in entity_type_filter
                ):
                    object_ids = [stix_output.id]

            if object_ids:
                linking_method(object_ids, parent)
                _logger.debug(
                    "Added refs to context",
                    {
                        "log_prefix": LOG_PREFIX,
                        "count": len(object_ids),
                        "context_key": context_key,
                    },
                )

        except Exception as e:
            _logger.warning(
                "Error adding refs", {"log_prefix": LOG_PREFIX, "error": str(e)}
            )

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
                "Mapper lacks create_relationship method",
                {"log_prefix": LOG_PREFIX, "mapper_class": str(mapper_class)},
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
                "Error creating relationship",
                {
                    "log_prefix": LOG_PREFIX,
                    "relationship_type": relationship_type,
                    "error": str(e),
                },
            )

        return result

    return postprocess


def _create_single_relationship(
    entity: Any,
    context_entity: Any,
    relationship_type: str,
    mapper_class: RelationshipMapper,
    reverse: bool,
) -> Any | None:
    """Create a single relationship between two entities."""
    if not (hasattr(entity, "id") and not hasattr(entity, "relationship_type")):
        return None

    try:
        if reverse:
            rel = mapper_class.create_relationship(
                entity, relationship_type, context_entity
            )
            _logger.debug(
                "Created reverse relationship",
                {
                    "log_prefix": LOG_PREFIX,
                    "relationship_type": relationship_type,
                    "source_id": entity.id,
                    "target_id": context_entity.id,
                },
            )
        else:
            rel = mapper_class.create_relationship(
                context_entity, relationship_type, entity
            )
            _logger.debug(
                "Created relationship",
                {
                    "log_prefix": LOG_PREFIX,
                    "relationship_type": relationship_type,
                    "source_id": context_entity.id,
                    "target_id": entity.id,
                },
            )

        return rel

    except Exception as e:
        _logger.warning(
            "Failed to create relationship",
            {
                "log_prefix": LOG_PREFIX,
                "relationship_type": relationship_type,
                "entity_id": entity.id,
                "error": str(e),
            },
        )
        return None


def _find_entity_in_output(stix_output: Any, context_key: str) -> Any:
    """Find entity in STIX output based on context key."""
    entity = None
    if isinstance(stix_output, list):
        for obj in stix_output:
            if hasattr(obj, "type") and obj.type == context_key.replace("_", "-"):
                entity = obj
                break
    elif hasattr(stix_output, "type"):
        entity = stix_output
    return entity


def _handle_set_operation(stix_output: Any, context_key: str) -> None:
    """Handle the 'set' operation for context management."""
    entity = _find_entity_in_output(stix_output, context_key)
    if entity:
        set_context(context_key, entity)
        _logger.debug(
            "Set context",
            {"log_prefix": LOG_PREFIX, "context_key": context_key},
        )


def _handle_clear_operation(context_key: str) -> None:
    """Handle the 'clear' operation for context management."""
    clear_context(context_key)
    _logger.debug(
        "Cleared context",
        {"log_prefix": LOG_PREFIX, "context_key": context_key},
    )


def _handle_clear_all_operation() -> None:
    """Handle the 'clear_all' operation for context management."""
    clear_all_contexts()
    _logger.debug("Cleared all contexts", {"log_prefix": LOG_PREFIX})


def manage_context(operation: str, context_key: str | None = None) -> Any:
    """Manage context storage.

    Args:
        operation: 'set' or 'clear' or 'clear_all'
        context_key: Key for set/clear operations

    """

    def postprocess(stix_output: Any) -> Any:
        try:
            match operation:
                case "set" if context_key:
                    _handle_set_operation(stix_output, context_key)
                case "clear" if context_key:
                    _handle_clear_operation(context_key)
                case "clear_all":
                    _handle_clear_all_operation()

        except Exception as e:
            _logger.warning(
                "Error managing context", {"log_prefix": LOG_PREFIX, "error": str(e)}
            )

        return stix_output

    return postprocess


def link_to_report(entity_type_filter: list[str] | None = None) -> Any:
    """Add objects to report's object_refs."""
    return add_to_refs(
        "report", GTIReportToSTIXReport.add_object_refs, entity_type_filter
    )


def link_main_entity_to_report(entity_types: list[str]) -> Any:
    """Add only main entities (by type) to report's object_refs."""
    return add_to_refs("report", GTIReportToSTIXReport.add_object_refs, entity_types)


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


def attributed_to_relationship(
    mapper_class: Any, source_context: str, reverse: bool = False
) -> Any:
    """Create 'attributed-to' relationships from source context."""
    return create_relationship("attributed-to", source_context, mapper_class, reverse)


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
                    "Created relationship",
                    {
                        "log_prefix": LOG_PREFIX,
                        "source_id": entity.id,
                        "target_id": report.id,
                    },
                )

        except Exception as e:
            _logger.warning(
                "Error creating context-to-report relationship",
                {"log_prefix": LOG_PREFIX, "error": str(e)},
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
                _logger.debug(
                    "Added entity to report refs",
                    {"log_prefix": LOG_PREFIX, "entity_id": entity.id},
                )

        except Exception as e:
            _logger.warning(
                "Error adding context to report refs",
                {"log_prefix": LOG_PREFIX, "error": str(e)},
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


def set_vulnerability_context() -> Any:
    """Store vulnerability in context for later use."""
    return set_context_for("vulnerability")


def entity_to_report(
    context_key: str, entity_type: str, relationship_creator: Any
) -> Any:
    """Create relationship + add ref from entity to report (mutualized function)."""

    def postprocess(stix_output: Any) -> Any:
        result = add_context_to_report_refs(context_key)(stix_output)

        return result

    return postprocess


def intrusion_set_to_report() -> Any:
    """Create relationship + add ref from intrusion set to report."""

    def postprocess(stix_output: Any) -> Any:
        result = add_context_to_report_refs("intrusion_set")(stix_output)

        return result

    return postprocess


def malware_family_to_report() -> Any:
    """Create relationship + add ref from malware family to report."""

    def postprocess(stix_output: Any) -> Any:
        result = add_context_to_report_refs("malware")(stix_output)

        return result

    return postprocess


def vulnerability_to_report() -> Any:
    """Create relationship + add ref from vulnerability to report."""

    def postprocess(stix_output: Any) -> Any:
        result = add_context_to_report_refs("vulnerability")(stix_output)

        return result

    return postprocess
