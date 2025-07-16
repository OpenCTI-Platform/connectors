"""Orchestrator for fetching and processing data.

This orchestrator handles the fetching, conversion, and processing data
using the proper fetchers/converters/batch processor pattern.
"""

import logging
import re
from typing import Any, Dict, Optional

from connector.src.custom.client_api import ClientAPI
from connector.src.custom.configs import BATCH_PROCESSOR_CONFIG, GTIConfig
from connector.src.custom.convert_to_stix import ConvertToSTIX
from connector.src.octi.work_manager import WorkManager
from connector.src.utils.batch_processors import GenericBatchProcessor

LOG_PREFIX = "[Orchestrator]"


class Orchestrator:
    """Orchestrator for fetching and processing data."""

    def __init__(
        self,
        work_manager: WorkManager,
        logger: logging.Logger,
        config: GTIConfig,
        tlp_level: str,
    ):
        """Initialize the Orchestrator.

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

        self.logger.info(f"{LOG_PREFIX} API URL: {self.config.api_url}")
        self.logger.info(
            f"{LOG_PREFIX} Import start date: {self.config.import_start_date}"
        )

        self.client_api = ClientAPI(config, logger)
        self.converter = ConvertToSTIX(config, logger, tlp_level)
        self.batch_processor = self._create_batch_processor()
        self.current: int = 0

    def _create_batch_processor(self) -> GenericBatchProcessor:
        """Create and configure the batch processor.

        Returns:
            Configured GenericBatchProcessor instance

        """
        return GenericBatchProcessor(
            work_manager=self.work_manager,
            config=BATCH_PROCESSOR_CONFIG,
            logger=self.logger,
        )

    async def run(self, initial_state: Optional[Dict[str, Any]]) -> None:
        """Run the orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        try:
            async for gti_reports in self.client_api.fetch_reports(initial_state):
                total_reports = len(gti_reports)
                for report_idx, report in enumerate(gti_reports):
                    report_entities = self.converter.convert_report_to_stix(report)
                    subentities_ids = await self.client_api.fetch_subentities_ids(
                        report.id
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
                            subentities_detailed, report_entities
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
                    if (
                        self.batch_processor.get_current_batch_size()
                        + len(all_entities)
                    ) >= self.batch_processor.config.batch_size:
                        self.logger.info(
                            f"{LOG_PREFIX} Need to Flush before adding next items to preserve consistency of the bundle"
                        )
                        self.batch_processor.flush()
                    self._update_report_index_inplace()
                    self.batch_processor.add_item(self.converter.organization)
                    self.batch_processor.add_item(self.converter.tlp_marking)
                    self.batch_processor.add_items(all_entities)
        finally:
            self._flush_batch_processor()

    def _update_report_index_inplace(self) -> None:
        """Update the work message to reflect current report progress."""

        def replacer(match: Any) -> str:
            actual_total = self.client_api.real_total_reports or 0

            if actual_total == 0:
                return "(~ 0/0 reports)"

            self.current += 1
            return f"(~ {self.current}/{actual_total} reports)"

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
