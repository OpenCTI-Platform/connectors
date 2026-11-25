"""Base orchestrator class with common functionality."""

import logging
from typing import Any, ClassVar

from connector.src.custom.client_api.client_api import ClientAPI
from connector.src.custom.configs import GTIConfig
from connector.src.octi.work_manager import WorkManager


class BaseOrchestrator:
    """Base orchestrator class with common functionality."""

    LOG_PREFIX: ClassVar[str] = "[BaseOrchestrator]"

    def __init__(
        self,
        work_manager: WorkManager,
        logger: logging.Logger,
        config: GTIConfig,
        tlp_level: str,
    ):
        """Initialize the Base Orchestrator.

        Args:
            work_manager: Work manager for handling OpenCTI work operations
            logger: Logger instance for logging
            config: Configuration object containing connector settings
            tlp_level: TLP level for the connector

        """
        self.work_manager = work_manager
        self.logger = logger
        self.config = config
        self.tlp_level = tlp_level.lower()

        self.client_api = ClientAPI(config, logger)

    def _log_relationships_summary(
        self, subentities: dict[str, Any], current_idx: int, total: int
    ) -> None:
        """Log the number of related entities found, by type.

        Args:
            subentities: Related entities grouped by type
            current_idx: Index of the entity being processed
            total: Number of entities in the page

        """
        rel_summary = ", ".join([f"{k}: {len(v)}" for k, v in subentities.items()])
        if len(rel_summary) > 0:
            self.logger.info(
                "Found relationships",
                {
                    "prefix": self.LOG_PREFIX,
                    "current": current_idx + 1,
                    "total": total,
                    "relationships": rel_summary,
                },
            )

    def _log_entities_summary(
        self, all_entities: list[Any], current_idx: int, total: int
    ) -> None:
        """Log the number of converted STIX objects, by type.

        Args:
            all_entities: Converted STIX objects
            current_idx: Index of the entity being processed
            total: Number of entities in the page

        """
        entity_types: dict[str, int] = {}
        for entity in all_entities:
            entity_type = getattr(entity, "type", None)
            if entity_type:
                entity_types[entity_type] = entity_types.get(entity_type, 0) + 1
        entities_summary = ", ".join([f"{k}: {v}" for k, v in entity_types.items()])
        self.logger.info(
            "Converted to STIX entities",
            {
                "prefix": self.LOG_PREFIX,
                "current": current_idx + 1,
                "total": total,
                "entities_count": len(all_entities),
                "entities_summary": entities_summary,
            },
        )

    def _check_batch_size_and_flush(
        self, batch_processor: Any, all_entities: list[Any]
    ) -> None:
        """Check if batch needs to be flushed and flush if necessary.

        Args:
            batch_processor: The batch processor to check
            all_entities: list of entities to be added

        """
        if (
            batch_processor.get_current_batch_size() + len(all_entities)
        ) >= batch_processor.config.batch_size * 2:
            self.logger.info(
                "Need to Flush before adding next items to preserve consistency of the bundle",
                {"prefix": self.LOG_PREFIX},
            )
            batch_processor.flush()

    def _add_entities_to_batch(
        self, batch_processor: Any, all_entities: list[Any], converter: Any
    ) -> None:
        """Add entities to the batch processor.

        Args:
            batch_processor: The batch processor to add entities to
            all_entities: list of entities to add
            converter: The converter instance to use for organization and tlp_marking

        """
        batch_processor.add_item(converter.organization)
        batch_processor.add_item(converter.tlp_marking)
        batch_processor.add_items(all_entities)
