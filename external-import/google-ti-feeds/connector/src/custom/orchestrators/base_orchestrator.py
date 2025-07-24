"""Base orchestrator class with common functionality."""

import logging
from typing import Any, Dict, List

from connector.src.custom.client_api.client_api import ClientAPI
from connector.src.custom.configs import GTIConfig
from connector.src.octi.work_manager import WorkManager

LOG_PREFIX = "[BaseOrchestrator]"


class BaseOrchestrator:
    """Base orchestrator class with common functionality."""

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
        self,
        subentities_ids: Dict[str, Any],
        current_idx: int,
        total: int,
        entity_type: str,
    ) -> None:
        """Log summary of relationships found.

        Args:
            subentities_ids: Dictionary of subentity IDs
            current_idx: Current index in processing
            total: Total number of entities
            entity_type: Type of entity being processed

        """
        rel_summary = ", ".join([f"{k}: {len(v)}" for k, v in subentities_ids.items()])
        if len(rel_summary) > 0:
            self.logger.info(
                f"[BaseOrchestrator] ({current_idx + 1}/{total}) Found relationships {{{rel_summary}}}"
            )

    def _log_entities_summary(
        self, all_entities: List[Any], current_idx: int, total: int, entity_type: str
    ) -> None:
        """Log summary of converted entities.

        Args:
            all_entities: List of all converted entities
            current_idx: Current index in processing
            total: Total number of entities
            entity_type: Type of entity being processed

        """
        entity_types: Dict[str, int] = {}
        for entity in all_entities:
            entity_type_attr = getattr(entity, "type", None)
            if entity_type_attr:
                entity_types[entity_type_attr] = (
                    entity_types.get(entity_type_attr, 0) + 1
                )
        entities_summary = ", ".join([f"{k}: {v}" for k, v in entity_types.items()])
        self.logger.info(
            f"[BaseOrchestrator] ({current_idx + 1}/{total}) Converted to {len(all_entities)} STIX entities {{{entities_summary}}}"
        )

    def _check_batch_size_and_flush(
        self, batch_processor: Any, all_entities: List[Any]
    ) -> None:
        """Check if batch needs to be flushed and flush if necessary.

        Args:
            batch_processor: The batch processor to check
            all_entities: List of entities to be added

        """
        if (
            batch_processor.get_current_batch_size() + len(all_entities)
        ) >= batch_processor.config.batch_size:
            self.logger.info(
                "[BaseOrchestrator] Need to Flush before adding next items to preserve consistency of the bundle"
            )
            batch_processor.flush()

    def _add_entities_to_batch(
        self, batch_processor: Any, all_entities: List[Any], converter: Any
    ) -> None:
        """Add entities to the batch processor.

        Args:
            batch_processor: The batch processor to add entities to
            all_entities: List of entities to add
            converter: The converter instance to use for organization and tlp_marking

        """
        batch_processor.add_item(converter.organization)
        batch_processor.add_item(converter.tlp_marking)
        batch_processor.add_items(all_entities)
