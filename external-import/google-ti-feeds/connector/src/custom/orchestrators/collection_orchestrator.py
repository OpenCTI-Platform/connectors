"""Template orchestrator for GTI collections imported with their sub-entities."""

import logging
import re
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any, ClassVar

from connector.src.custom.client_api.inline_relationships import (
    is_subentity_call_needed,
)
from connector.src.custom.configs import GTIConfig
from connector.src.custom.configs.gti_config_common import IOC_SUBENTITY_TYPES
from connector.src.custom.convert_to_stix.convert_to_stix_base import (
    INTRUSION_SET_CAPABILITY_RELATIONSHIP_TYPES,
    BaseConvertToSTIX,
    ioc_threat_relationship_types,
)
from connector.src.custom.models.gti.gti_attack_technique_id_model import (
    GTIAttackTechniqueIDData,
)
from connector.src.custom.orchestrators.base_orchestrator import BaseOrchestrator
from connector.src.octi.work_manager import WorkManager
from connector.src.utils.batch_processors import (
    GenericBatchProcessor,
    GenericBatchProcessorConfig,
)


class CollectionOrchestrator(BaseOrchestrator, ABC):
    """Fetch a GTI collection, its sub-entities, convert them and send them in batches.

    Subclasses declare the collection through the class attributes and the
    abstract accessors, and override the hooks to add collection-specific objects.
    """

    # Main entity name passed to the converters, e.g. "malware_family".
    collection: ClassVar[str]
    # Plural label of the progress counter in the work name, e.g. "malware families".
    progress_label: ClassVar[str]
    converter_class: ClassVar[type[BaseConvertToSTIX]]
    batch_processor_config: ClassVar[GenericBatchProcessorConfig]

    def __init__(
        self,
        work_manager: WorkManager,
        logger: logging.Logger,
        config: GTIConfig,
        tlp_level: str,
    ):
        """Initialize the orchestrator.

        Args:
            work_manager: Work manager for handling OpenCTI work operations
            logger: Logger instance for logging
            config: Configuration object containing connector settings
            tlp_level: TLP level for the connector

        """
        super().__init__(work_manager, logger, config, tlp_level)

        self.logger.info(
            "API URL",
            {
                "prefix": self.LOG_PREFIX,
                "api_url": self.config.api_url.unicode_string(),
            },
        )
        self.logger.info(
            "Import start date",
            {"prefix": self.LOG_PREFIX, "start_date": self._import_start_date()},
        )

        self.converter: Any = self.converter_class(config, logger, tlp_level)
        self.batch_processor = self._create_batch_processor()
        self.nb_current: int = 0

    @abstractmethod
    def _subentity_types(self) -> list[str]:
        """Return the configured sub-entity types to fetch."""

    @abstractmethod
    def _import_start_date(self) -> timedelta:
        """Return the configured import start date."""

    @abstractmethod
    def _fetch(self, initial_state: dict[str, Any] | None) -> AsyncIterator[Any]:
        """Return the pages of entities fetched from GTI."""

    @abstractmethod
    def _convert(self, entity: Any) -> list[Any]:
        """Convert a main entity to STIX objects."""

    @abstractmethod
    def _progress_total(self) -> int | None:
        """Return the total number of entities reported by GTI."""

    @staticmethod
    def _main_entity(main_entities: list[Any], stix_type: str) -> Any | None:
        """Return the first main entity of a STIX type, e.g. the report."""
        return next(
            (
                entity
                for entity in main_entities
                if getattr(entity, "type", None) == stix_type
            ),
            None,
        )

    def _link_co_occurring_entities(
        self,
        main_entities: list[Any],
        subentity_stix: list[Any],
        subentities: dict[str, list[Any]] | None = None,
    ) -> list[Any]:
        """Return relationships between the sub-entities. None by default.

        Args:
            main_entities: STIX objects of the main entity.
            subentity_stix: Converted sub-entities of the main entity.
            subentities: GTI sub-entities of the main entity, by type.

        Returns:
            The created relationships.

        """
        return []

    async def _add_linked_subentities(
        self, entity: Any, subentities: dict[str, list[Any]]
    ) -> set[str]:
        """Add sub-entities GTI does not list for the entity, in place. None by default.

        Args:
            entity: The GTI main entity.
            subentities: GTI sub-entities of the main entity, by type.

        Returns:
            GTI collection IDs of the added sub-entities.

        """
        return set()

    def _link_linked_entities(
        self,
        main_entities: list[Any],
        subentity_stix: list[Any],
        linked_ids: set[str],
    ) -> list[Any]:
        """Return relationships to the sub-entities added by `_add_linked_subentities`.

        None by default.

        Args:
            main_entities: STIX objects of the main entity.
            subentity_stix: Converted sub-entities of the main entity.
            linked_ids: GTI collection IDs returned by `_add_linked_subentities`.

        Returns:
            The created relationships.

        """
        return []

    async def _finalize_entities(
        self, entity: Any, all_entities: list[Any]
    ) -> list[Any]:
        """Return the STIX objects to send for an entity. Unchanged by default.

        Args:
            entity: The GTI main entity.
            all_entities: STIX objects of the entity and its sub-entities.

        Returns:
            The STIX objects to send.

        """
        return all_entities

    def _create_batch_processor(self) -> GenericBatchProcessor:
        """Create and configure the batch processor.

        Returns:
            Configured GenericBatchProcessor instance

        """
        return GenericBatchProcessor(
            work_manager=self.work_manager,
            config=self.batch_processor_config,
            logger=self.logger,
        )

    async def run(self, initial_state: dict[str, Any] | None) -> None:
        """Run the orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        subentity_types = self._subentity_types()
        try:
            async for entities in self._fetch(initial_state):
                total = len(entities)
                for idx, entity in enumerate(entities):
                    self._update_index_inplace()
                    main_entities = self._convert(entity)
                    subentities = await self.client_api.fetch_subentities(
                        entity_name="entity_id",
                        entity_id=entity.id,
                        subentity_types=self._skip_iocs_above_threshold(
                            self._filter_subentity_types(subentity_types, entity),
                            entity,
                        ),
                    )
                    linked_ids = await self._add_linked_subentities(entity, subentities)
                    self._log_relationships_summary(subentities, idx, total)
                    self._use_attack_technique_ids(subentities)

                    subentity_stix = (
                        self.converter.convert_subentities_to_stix_with_linking(
                            subentities=subentities,
                            main_entity=self.collection,
                            main_entities=main_entities,
                        )
                        or []
                    )
                    if subentity_stix:
                        subentity_stix += self._link_co_occurring_entities(
                            main_entities, subentity_stix, subentities
                        )
                        subentity_stix += self._link_linked_entities(
                            main_entities, subentity_stix, linked_ids
                        )

                    all_entities = await self._finalize_entities(
                        entity, main_entities + subentity_stix
                    )
                    self._log_entities_summary(all_entities, idx, total)
                    self._check_batch_size_and_flush(self.batch_processor, all_entities)
                    self._add_entities_to_batch(
                        self.batch_processor, all_entities, self.converter
                    )
        finally:
            self._flush_batch_processor()

    def _use_attack_technique_ids(self, subentities: dict[str, list[Any]]) -> None:
        """Replace the fetched attack techniques by their IDs, in place.

        The attack patterns are built from the MITRE IDs alone (quota optimization).
        """
        attack_technique_ids = [
            attack_technique.id
            for attack_technique in subentities.pop("attack_techniques", [])
            if getattr(attack_technique, "id", None)
        ]
        if not attack_technique_ids:
            return
        self.logger.info(
            "Using ID-only approach for attack techniques (quota optimization)",
            {
                "prefix": self.LOG_PREFIX,
                "attack_technique_count": len(attack_technique_ids),
            },
        )
        subentities["attack_techniques"] = [
            GTIAttackTechniqueIDData.from_id_list(attack_technique_ids)
        ]

    @staticmethod
    def _filter_subentity_types(subentity_types: list[str], entity: Any) -> list[str]:
        """Filter subentity types based on the entity's counters.

        When the entity exposes a ``counters`` object (via ``attributes.counters``),
        subentity types whose counter is explicitly ``0`` are removed from the
        list to avoid unnecessary API calls.

        When the entity carries inline relationship descriptors (list call made
        with ``relationships=``), subentity types that the descriptors prove
        empty are removed too. See ``client_api/inline_relationships.py``.

        See: https://github.com/OpenCTI-Platform/connectors/issues/6562

        Args:
            subentity_types: The full list of subentity types to fetch.
            entity: The GTI entity object (must have ``attributes.counters``).

        Returns:
            A filtered list of subentity types worth fetching.

        """
        counters = getattr(getattr(entity, "attributes", None), "counters", None)
        if counters is not None:
            subentity_types = [
                subentity_type
                for subentity_type in subentity_types
                if getattr(counters, subentity_type, None) != 0
            ]

        relationships = getattr(entity, "relationships", None)
        return [
            subentity_type
            for subentity_type in subentity_types
            if is_subentity_call_needed(subentity_type, relationships)
        ]

    def _skip_iocs_above_threshold(
        self, subentity_types: list[str], entity: Any
    ) -> list[str]:
        """Drop IOC sub-entity types when the entity references too many IOCs.

        The IOC count comes from ``attributes.counters.iocs``. Entities without
        counters, or with the threshold unset, keep every sub-entity type.

        Args:
            subentity_types: The sub-entity types to fetch.
            entity: The GTI report or campaign.

        Returns:
            The sub-entity types to fetch.

        """
        threshold = getattr(self.config, "ioc_import_threshold", None)
        counters = getattr(getattr(entity, "attributes", None), "counters", None)
        ioc_count = getattr(counters, "iocs", None)
        if threshold is None or ioc_count is None or ioc_count <= threshold:
            return subentity_types

        self.logger.warning(
            "IOC count above threshold, skipping IOC sub-entities",
            {
                "prefix": self.LOG_PREFIX,
                "entity_id": getattr(entity, "id", None),
                "ioc_count": ioc_count,
                "ioc_import_threshold": threshold,
            },
        )
        return [
            subentity_type
            for subentity_type in subentity_types
            if subentity_type not in IOC_SUBENTITY_TYPES
        ]

    def _co_occurrence_relationship_types(
        self, ioc_threat_types: tuple[str, ...]
    ) -> dict[tuple[str, str], str]:
        """Return the enabled co-occurrence rules.

        Args:
            ioc_threat_types: STIX types IOCs are linked to.

        Returns:
            Relationship type keyed by (source, target) STIX type.

        """
        relationship_types: dict[tuple[str, str], str] = {}
        if self.config.ioc_link_to_threats:
            relationship_types |= ioc_threat_relationship_types(ioc_threat_types)
        if self.config.intrusion_set_link_to_capabilities:
            relationship_types |= INTRUSION_SET_CAPABILITY_RELATIONSHIP_TYPES
        return relationship_types

    def _update_index_inplace(self) -> None:
        """Update the progress counter of the work name, e.g. '(~ 3/10 reports)'."""
        label = re.escape(self.progress_label)

        def replacer(match: Any) -> str:
            actual_total = self._progress_total() or 0
            if actual_total == 0:
                return f"(~ 0/0 {self.progress_label})"
            self.nb_current += 1
            return f"(~ {self.nb_current}/{actual_total} {self.progress_label})"

        template = self.batch_processor.config.work_name_template
        self.batch_processor.config.work_name_template = re.sub(
            rf"\(~ (\d+)/(\d+) {label}\)", replacer, template
        )

    def _flush_batch_processor(self) -> None:
        """Flush any remaining items in the batch processor."""
        try:
            work_id = self.batch_processor.flush()
            if work_id:
                self.logger.info(
                    "Batch processor: Flushed remaining items",
                    {"prefix": self.LOG_PREFIX},
                )
            self.batch_processor.update_final_state()
        except Exception as e:
            self.logger.error(
                "Failed to flush batch processor",
                {"prefix": self.LOG_PREFIX, "error": str(e)},
            )
