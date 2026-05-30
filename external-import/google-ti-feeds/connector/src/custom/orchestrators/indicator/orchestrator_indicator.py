"""Indicator-specific orchestrator for fetching and processing IOC delta data."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from connector.src.custom.configs import GTIConfig
from connector.src.custom.configs.indicator.batch_processor_config_indicator import (
    INDICATOR_BATCH_PROCESSOR_CONFIG,
)
from connector.src.custom.convert_to_stix.indicator.convert_to_stix_indicator import (
    ConvertToSTIXIndicator,
)
from connector.src.custom.orchestrators.base_orchestrator import BaseOrchestrator
from connector.src.octi.work_manager import WorkManager
from connector.src.utils.batch_processors import GenericBatchProcessor

LOG_PREFIX = "[OrchestratorIndicator]"


class OrchestratorIndicator(BaseOrchestrator):
    """Indicator-specific orchestrator for fetching and processing IOC delta data."""

    def __init__(
        self,
        work_manager: WorkManager,
        logger: logging.Logger,
        config: GTIConfig,
        tlp_level: str,
    ):
        super().__init__(work_manager, logger, config, tlp_level)

        self.logger.info(
            "Indicator import start date",
            {
                "prefix": LOG_PREFIX,
                "start_date": self.config.indicator_import_start_date,
            },
        )

        self.converter = ConvertToSTIXIndicator(config, logger, tlp_level)
        self.batch_processor = self._create_batch_processor()

    def _create_batch_processor(self) -> GenericBatchProcessor:
        return GenericBatchProcessor(
            work_manager=self.work_manager,
            config=INDICATOR_BATCH_PROCESSOR_CONFIG,
            logger=self.logger,
        )

    def _get_start_datetime(self, initial_state: dict[str, Any] | None) -> datetime:
        """Determine start datetime from state or config."""
        if initial_state:
            last_run = initial_state.get("indicator_last_run_datetime")
            if last_run:
                try:
                    last_dt = datetime.fromisoformat(last_run)
                    if last_dt.tzinfo is None:
                        last_dt = last_dt.replace(tzinfo=timezone.utc)
                    return last_dt + timedelta(hours=1)
                except ValueError:
                    self.logger.warning(
                        "Invalid last run datetime format in state, falling back to config",
                        {"prefix": LOG_PREFIX, "last_run": last_run},
                    )

        lookback = self.config.indicator_import_start_date
        return datetime.now(timezone.utc) - lookback

    async def run(self, initial_state: dict[str, Any] | None) -> None:
        """Run the indicator orchestrator."""
        self.logger.info("Starting indicator orchestration", {"prefix": LOG_PREFIX})

        now = datetime.now(timezone.utc)
        start_dt = self._get_start_datetime(initial_state)

        if start_dt >= now:
            self.logger.info(
                "No new packages to process (start_dt >= now)",
                {"prefix": LOG_PREFIX, "start_dt": start_dt.isoformat()},
            )
            return

        self.logger.info(
            "Processing IOC delta packages",
            {
                "prefix": LOG_PREFIX,
                "start_dt": start_dt.isoformat(),
                "now": now.isoformat(),
            },
        )

        current_dt = start_dt
        while current_dt < now:
            package_id = current_dt.strftime("%Y%m%d%H")

            self.logger.info(
                "Processing IOC delta package",
                {"prefix": LOG_PREFIX, "package_id": package_id},
            )

            for ioc_type in self.config.indicator_types:
                await self._process_package(package_id, ioc_type)

            self.work_manager.update_state(
                state_key="indicator_last_run_datetime",
                date_str=current_dt.isoformat(),
            )

            current_dt += timedelta(hours=1)
            self.batch_processor.flush()

    async def _process_package(self, package_id: str, ioc_type: str) -> None:
        """Fetch and process a single IOC delta package."""
        try:
            raw_entries = await self.client_api.fetch_ioc_delta_package(
                package_id, ioc_type
            )
            if not raw_entries:
                return

            self.logger.info(
                "Fetched IOC delta entries",
                {
                    "prefix": LOG_PREFIX,
                    "package_id": package_id,
                    "ioc_type": ioc_type,
                    "count": len(raw_entries),
                },
            )

            all_stix: list[Any] = []
            for entry_data in raw_entries:
                stix_objects = self.converter.convert(entry_data)
                all_stix.extend(stix_objects)

            if all_stix:
                self._add_entities_to_batch(
                    self.batch_processor, all_stix, self.converter
                )

        except Exception as e:
            self.logger.warning(
                "Error processing IOC delta package",
                {
                    "prefix": LOG_PREFIX,
                    "package_id": package_id,
                    "ioc_type": ioc_type,
                    "error": str(e),
                },
            )
