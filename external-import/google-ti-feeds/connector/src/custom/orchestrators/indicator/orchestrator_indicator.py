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
from connector.src.custom.exceptions import GTIIndicatorPackageUnavailableError
from connector.src.custom.orchestrators.base_orchestrator import BaseOrchestrator
from connector.src.octi.work_manager import WorkManager
from connector.src.utils.batch_processors import GenericBatchProcessor

LOG_PREFIX = "[OrchestratorIndicator]"
# IOC delta packages cover one clock hour and are published after it closes.
PACKAGE_WINDOW = timedelta(hours=1)


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
        """Determine start datetime from state or config.

        State on an hour boundary names the last package fully processed, so the
        next run starts one hour later. State off the boundary was written before
        closed-hour processing, when the recorded hour could still have been in
        progress and never fetched, so that hour is retried.
        """
        if initial_state:
            last_run = initial_state.get("indicator_last_run_datetime")
            if last_run:
                try:
                    last_dt = datetime.fromisoformat(last_run)
                    if last_dt.tzinfo is None:
                        last_dt = last_dt.replace(tzinfo=timezone.utc)
                    last_hour = last_dt.replace(minute=0, second=0, microsecond=0)
                    if last_dt != last_hour:
                        return last_hour
                    return last_dt + PACKAGE_WINDOW
                except ValueError:
                    self.logger.warning(
                        "Invalid last run datetime format in state, falling back to config",
                        {"prefix": LOG_PREFIX, "last_run": last_run},
                    )

        lookback = self.config.indicator_import_start_date
        return datetime.now(timezone.utc) - lookback

    async def run(self, initial_state: dict[str, Any] | None) -> None:
        """Run the indicator orchestrator.

        Only hours that have fully closed are requested. An hour is recorded in
        state after its objects have been sent, and processing stops at the first
        package that is not available yet so that it is retried on the next run
        instead of being skipped.
        """
        self.logger.info("Starting indicator orchestration", {"prefix": LOG_PREFIX})

        now = datetime.now(timezone.utc)
        start_dt = self._get_start_datetime(initial_state).replace(
            minute=0, second=0, microsecond=0
        )

        if start_dt + PACKAGE_WINDOW > now:
            self.logger.info(
                "No new packages to process (next package hour has not closed)",
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
        while current_dt + PACKAGE_WINDOW <= now:
            package_id = current_dt.strftime("%Y%m%d%H")

            self.logger.info(
                "Processing IOC delta package",
                {"prefix": LOG_PREFIX, "package_id": package_id},
            )

            try:
                entries_by_type = await self._fetch_package(package_id)
            except GTIIndicatorPackageUnavailableError as e:
                self.logger.info(
                    "IOC delta package unavailable, will retry on next run",
                    {
                        "prefix": LOG_PREFIX,
                        "package_id": package_id,
                        "status": e.status_code,
                    },
                )
                return

            for ioc_type, raw_entries in entries_by_type.items():
                self._add_package_to_batch(package_id, ioc_type, raw_entries)

            self.batch_processor.flush()
            self.work_manager.update_state(
                state_key="indicator_last_run_datetime",
                date_str=current_dt.isoformat(),
            )
            current_dt += PACKAGE_WINDOW

    async def _fetch_package(self, package_id: str) -> dict[str, list[Any]]:
        """Fetch every configured IOC type of one package before any is converted.

        Raises:
            GTIIndicatorPackageUnavailableError: Any IOC type of the package is not
                available yet, so nothing from this package may be sent.

        """
        entries_by_type: dict[str, list[Any]] = {}
        for ioc_type in self.config.indicator_types:
            raw_entries = await self._fetch_package_entries(package_id, ioc_type)
            if raw_entries:
                entries_by_type[ioc_type] = raw_entries
        return entries_by_type

    async def _fetch_package_entries(
        self, package_id: str, ioc_type: str
    ) -> list[Any] | None:
        """Fetch one IOC type of a package; other fetch errors skip that type."""
        try:
            raw_entries = await self.client_api.fetch_ioc_delta_package(
                package_id, ioc_type
            )
        except GTIIndicatorPackageUnavailableError:
            raise
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
            return None

        if raw_entries:
            self.logger.info(
                "Fetched IOC delta entries",
                {
                    "prefix": LOG_PREFIX,
                    "package_id": package_id,
                    "ioc_type": ioc_type,
                    "count": len(raw_entries),
                },
            )
        return raw_entries

    def _add_package_to_batch(
        self, package_id: str, ioc_type: str, raw_entries: list[Any]
    ) -> None:
        """Convert one IOC type's entries to STIX and add them to the batch."""
        try:
            all_stix: list[Any] = []
            for entry_data in raw_entries:
                all_stix.extend(self.converter.convert(entry_data))

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
