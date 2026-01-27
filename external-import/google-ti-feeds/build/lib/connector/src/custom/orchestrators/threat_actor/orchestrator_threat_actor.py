"""Threat actor-specific orchestrator for fetching and processing threat actor data."""

import logging
import re
from typing import Any

from connector.src.custom.configs import (
    THREAT_ACTOR_BATCH_PROCESSOR_CONFIG,
    GTIConfig,
)
from connector.src.custom.convert_to_stix.threat_actor.convert_to_stix_threat_actor import (
    ConvertToSTIXThreatActor,
)
from connector.src.custom.models.gti.gti_attack_technique_id_model import (
    GTIAttackTechniqueIDData,
)
from connector.src.custom.orchestrators.base_orchestrator import BaseOrchestrator
from connector.src.octi.work_manager import WorkManager
from connector.src.utils.batch_processors import GenericBatchProcessor

LOG_PREFIX = "[OrchestratorThreatActor]"


class OrchestratorThreatActor(BaseOrchestrator):
    """Threat actor-specific orchestrator for fetching and processing threat actor data."""

    def __init__(
        self,
        work_manager: WorkManager,
        logger: logging.Logger,
        config: GTIConfig,
        tlp_level: str,
    ):
        """Initialize the Threat Actor Orchestrator.

        Args:
            work_manager: Work manager for handling OpenCTI work operations
            logger: Logger instance for logging
            config: Configuration object containing connector settings
            tlp_level: TLP level for the connector

        """
        super().__init__(work_manager, logger, config, tlp_level)

        self.logger.info(
            "API URL",
            {"prefix": LOG_PREFIX, "api_url": self.config.api_url.unicode_string()},
        )
        self.logger.info(
            "Threat actor import start date",
            {
                "prefix": LOG_PREFIX,
                "start_date": self.config.threat_actor_import_start_date,
            },
        )

        self.converter = ConvertToSTIXThreatActor(config, logger, tlp_level)
        self.batch_processor = self._create_batch_processor()
        self.nb_current: int = 0

    def _create_batch_processor(self) -> GenericBatchProcessor:
        """Create and configure the threat actor batch processor.

        Returns:
            Configured GenericBatchProcessor instance

        """
        return GenericBatchProcessor(
            work_manager=self.work_manager,
            config=THREAT_ACTOR_BATCH_PROCESSOR_CONFIG,
            logger=self.logger,
        )

    async def run(self, initial_state: dict[str, Any] | None) -> None:
        """Run the threat actor orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        subentity_types = [
            "malware_families",
            "attack_techniques",
            "vulnerabilities",
            # "campaigns",
            # "reports",
            # "domains",
            # "files",
            # "urls",
            # "ip_addresses",
        ]
        try:
            async for gti_threat_actors in self.client_api.fetch_threat_actors(
                initial_state
            ):
                total_threat_actors = len(gti_threat_actors)
                for threat_actor_idx, threat_actor in enumerate(gti_threat_actors):
                    self._update_index_inplace()
                    threat_actor_entities = self.converter.convert_threat_actor_to_stix(
                        threat_actor
                    )
                    subentities_ids = await self.client_api.fetch_subentities_ids(
                        entity_name="entity_id",
                        entity_id=threat_actor.id,
                        subentity_types=subentity_types,
                    )

                    rel_summary = ", ".join(
                        [f"{k}: {len(v)}" for k, v in subentities_ids.items()]
                    )
                    if len(rel_summary) > 0:
                        self.logger.info(
                            "Found relationships",
                            {
                                "prefix": LOG_PREFIX,
                                "current": threat_actor_idx + 1,
                                "total": total_threat_actors,
                                "relationships": rel_summary,
                            },
                        )

                    # Skip fetch_subentity_details for attack_techniques (quota optimization)
                    attack_technique_ids = subentities_ids.get("attack_techniques", [])
                    filtered_subentities_ids = {
                        k: v
                        for k, v in subentities_ids.items()
                        if k != "attack_techniques"
                    }

                    if attack_technique_ids:
                        self.logger.info(
                            "Using ID-only approach for attack techniques (quota optimization)",
                            {
                                "prefix": LOG_PREFIX,
                                "attack_technique_count": len(attack_technique_ids),
                            },
                        )

                    subentities_detailed = (
                        await self.client_api.fetch_subentity_details(
                            filtered_subentities_ids
                        )
                    )

                    # Convert attack technique IDs to proper model format for conversion
                    if attack_technique_ids:
                        attack_technique_data = GTIAttackTechniqueIDData.from_id_list(
                            attack_technique_ids
                        )
                        subentities_detailed["attack_techniques"] = [
                            attack_technique_data
                        ]
                    subentity_stix = (
                        self.converter.convert_subentities_to_stix_with_linking(
                            subentities=subentities_detailed,
                            main_entity="threat_actor",
                            main_entities=threat_actor_entities,
                        )
                    )

                    all_entities = threat_actor_entities + (subentity_stix or [])

                    entity_types: dict[str, int] = {}
                    for entity in all_entities:
                        entity_type = getattr(entity, "type", None)
                        if entity_type:
                            entity_types[entity_type] = (
                                entity_types.get(entity_type, 0) + 1
                            )
                    entities_summary = ", ".join(
                        [f"{k}: {v}" for k, v in entity_types.items()]
                    )
                    self.logger.info(
                        "Converted to STIX entities",
                        {
                            "prefix": LOG_PREFIX,
                            "current": threat_actor_idx + 1,
                            "total": total_threat_actors,
                            "entities_count": len(all_entities),
                            "entities_summary": entities_summary,
                        },
                    )

                    self._check_batch_size_and_flush(self.batch_processor, all_entities)
                    self._add_entities_to_batch(
                        self.batch_processor, all_entities, self.converter
                    )
        finally:
            self._flush_batch_processor()

    def _update_index_inplace(self) -> None:
        """Update the work message to reflect current threat actor progress."""

        def replacer(match: Any) -> str:
            actual_total = self.client_api.real_total_threat_actors or 0

            if actual_total == 0:
                return "(~ 0/0 threat actors)"

            self.nb_current += 1
            return f"(~ {self.nb_current}/{actual_total} threat actors)"

        pattern = r"\(~ (\d+)/(\d+) threat actors\)"
        template = self.batch_processor.config.work_name_template
        self.batch_processor.config.work_name_template = re.sub(
            pattern, replacer, template
        )

    def _flush_batch_processor(self) -> None:
        """Flush any remaining items in the threat actor batch processor."""
        try:
            work_id = self.batch_processor.flush()
            if work_id:
                self.logger.info(
                    "Threat actor batch processor: Flushed remaining items",
                    {"prefix": LOG_PREFIX},
                )
            self.batch_processor.update_final_state()
        except Exception as e:
            self.logger.error(
                "Failed to flush threat actor batch processor",
                {"prefix": LOG_PREFIX, "error": str(e)},
            )
