"""Report-specific orchestrator for fetching and processing report data."""

import logging
import re
from typing import Any, Dict, Optional

from connector.src.custom.configs import (
    REPORT_BATCH_PROCESSOR_CONFIG,
    GTIConfig,
)
from connector.src.custom.convert_to_stix.report.convert_to_stix_report import (
    ConvertToSTIXReport,
)
from connector.src.custom.orchestrators.base_orchestrator import BaseOrchestrator
from connector.src.octi.work_manager import WorkManager
from connector.src.utils.batch_processors import GenericBatchProcessor

LOG_PREFIX = "[OrchestratorReport]"


class OrchestratorReport(BaseOrchestrator):
    """Report-specific orchestrator for fetching and processing report data."""

    def __init__(
        self,
        work_manager: WorkManager,
        logger: logging.Logger,
        config: GTIConfig,
        tlp_level: str,
    ):
        """Initialize the Report Orchestrator.

        Args:
            work_manager: Work manager for handling OpenCTI work operations
            logger: Logger instance for logging
            config: Configuration object containing connector settings
            tlp_level: TLP level for the connector

        """
        super().__init__(work_manager, logger, config, tlp_level)

        self.logger.info(f"{LOG_PREFIX} API URL: {self.config.api_url}")
        self.logger.info(
            f"{LOG_PREFIX} Report import start date: {self.config.report_import_start_date}"
        )

        self.converter = ConvertToSTIXReport(config, logger, tlp_level)
        self.batch_processor = self._create_batch_processor()
        self.nb_current: int = 0

    def _create_batch_processor(self) -> GenericBatchProcessor:
        """Create and configure the batch processor.

        Returns:
            Configured GenericBatchProcessor instance

        """
        return GenericBatchProcessor(
            work_manager=self.work_manager,
            config=REPORT_BATCH_PROCESSOR_CONFIG,
            logger=self.logger,
        )

    async def run(self, initial_state: Optional[Dict[str, Any]]) -> None:
        """Run the report orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        subentity_types = [
            "malware_families",
            "threat_actors",
            "attack_techniques",
            "vulnerabilities",
            "domains",
            "files",
            "urls",
            "ip_addresses",
        ]
        try:
            async for gti_reports in self.client_api.fetch_reports(initial_state):
                total_reports = len(gti_reports)
                for report_idx, report in enumerate(gti_reports):
                    report_entities = self.converter.convert_report_to_stix(report)
                    subentities_ids = await self.client_api.fetch_subentities_ids(
                        entity_name="entity_id",
                        entity_id=report.id,
                        subentity_types=subentity_types,
                    )

                    rel_summary = ", ".join(
                        [f"{k}: {len(v)}" for k, v in subentities_ids.items()]
                    )
                    if len(rel_summary) > 0:
                        self.logger.info(
                            f"{LOG_PREFIX} ({report_idx + 1}/{total_reports}) Found relationships {{{rel_summary}}}"
                        )

                    subentities_detailed = (
                        await self.client_api.fetch_subentity_details(subentities_ids)
                    )
                    subentity_stix = (
                        self.converter.convert_subentities_to_stix_with_linking(
                            subentities=subentities_detailed,
                            main_entity="report",
                            main_entities=report_entities,
                        )
                    )

                    all_entities = report_entities + (subentity_stix or [])

                    entity_types: Dict[str, int] = {}
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
                        f"{LOG_PREFIX} ({report_idx + 1}/{total_reports}) Converted to {len(all_entities)} STIX entities {{{entities_summary}}}"
                    )

                    self._check_batch_size_and_flush(self.batch_processor, all_entities)
                    self._update_index_inplace()
                    self._add_entities_to_batch(
                        self.batch_processor, all_entities, self.converter
                    )
        finally:
            self._flush_batch_processor()

    def _update_index_inplace(self) -> None:
        """Update the work message to reflect current report progress."""

        def replacer(match: Any) -> str:
            actual_total = self.client_api.real_total_reports or 0

            if actual_total == 0:
                return "(~ 0/0 reports)"

            self.nb_current += 1
            return f"(~ {self.nb_current}/{actual_total} reports)"

        pattern = r"\(~ (\d+)/(\d+) reports\)"
        template = self.batch_processor.config.work_name_template
        self.batch_processor.config.work_name_template = re.sub(
            pattern, replacer, template
        )

    def _flush_batch_processor(self) -> None:
        """Flush any remaining items in the batch processor."""
        try:
            work_id = self.batch_processor.flush()
            if work_id:
                self.logger.info(
                    f"{LOG_PREFIX} Batch processor: Flushed remaining items"
                )
            self.batch_processor.update_final_state()
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Failed to flush batch processor: {str(e)}")
