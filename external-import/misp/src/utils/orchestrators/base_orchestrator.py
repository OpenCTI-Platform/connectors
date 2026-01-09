"""Base orchestrator class with common functionality."""

from typing import TYPE_CHECKING, Any

from api_client.client import MISPClient

if TYPE_CHECKING:
    import stix2
    from connector.settings import MispConfig
    from utils.batch_processors.generic_batch_processor import GenericBatchProcessor
    from utils.protocols import LoggerProtocol
    from utils.work_manager import WorkManager


LOG_PREFIX = "[BaseOrchestrator]"


class BaseOrchestrator:
    """Base orchestrator class with common functionality."""

    def __init__(
        self,
        work_manager: "WorkManager",
        logger: "LoggerProtocol",
        config: "MispConfig",
    ) -> None:
        """Initialize the Base Orchestrator.

        Args:
            work_manager: Work manager for handling OpenCTI work operations
            logger: Logger instance for logging
            config: Configuration object containing connector settings

        """
        self.work_manager = work_manager
        self.logger = logger
        self.config = config

        self.client_api: MISPClient = MISPClient(
            url=self.config.url,
            key=self.config.key.get_secret_value(),
            verify_ssl=self.config.ssl_verify,
            certificate=self.config.client_cert,
        )

    def _log_relationships_summary(
        self,
        subentities_ids: dict[str, Any],
        current_idx: int,
        total: int,
    ) -> None:
        """Log summary of relationships found.

        Args:
            subentities_ids: dictionary of subentity IDs
            current_idx: Current index in processing
            total: Total number of entities

        """
        rel_summary = ", ".join([f"{k}: {len(v)}" for k, v in subentities_ids.items()])
        if len(rel_summary) > 0:
            self.logger.info(
                "Found relationships",
                {
                    "prefix": LOG_PREFIX,
                    "current": current_idx + 1,
                    "total": total,
                    "relationships": rel_summary,
                },
            )

    def _log_entities_summary(
        self,
        all_entities: list[Any],
        current_idx: int,
        total: int,
    ) -> None:
        """Log summary of converted entities.

        Args:
            all_entities: list of all converted entities
            current_idx: Current index in processing
            total: Total number of entities

        """
        entity_types: dict[str, int] = {}
        for entity in all_entities:
            entity_type_attr = getattr(entity, "type", None)
            if entity_type_attr:
                entity_types[entity_type_attr] = (
                    entity_types.get(entity_type_attr, 0) + 1
                )
        entities_summary = ", ".join([f"{k}: {v}" for k, v in entity_types.items()])
        self.logger.info(
            "Converted to STIX entities",
            {
                "prefix": LOG_PREFIX,
                "current": current_idx + 1,
                "total": total,
                "entities_count": len(all_entities),
                "entities_summary": entities_summary,
            },
        )

    def _check_batch_size_and_flush(
        self,
        batch_processor: Any,
        all_entities: list[Any],
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
                {"prefix": LOG_PREFIX},
            )
            batch_processor.flush()

    def _add_entities_to_batch(
        self,
        batch_processor: "GenericBatchProcessor",
        all_entities: "list[stix2.v21._STIXBase21]",
        author,
        markings,
    ) -> None:
        """Add entities to the batch processor.

        Args:
            batch_processor: The batch processor to add entities to
            all_entities: list of entities to add
            converter: The converter instance to use for organization and tlp_marking

        """
        batch_processor.add_item(author)
        batch_processor.add_items(markings)
        batch_processor.add_items(all_entities)
