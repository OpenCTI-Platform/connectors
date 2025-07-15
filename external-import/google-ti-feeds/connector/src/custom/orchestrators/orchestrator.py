"""Orchestrator for fetching and processing data.

This orchestrator handles the fetching, conversion, and processing data
using the proper fetchers/converters/batch processor pattern.
"""

import logging
from typing import Any, Dict, Optional

from connector.src.custom.configs import GTIConfig
from connector.src.custom.orchestrators.malware.orchestrator_malware import (
    OrchestratorMalware,
)
from connector.src.custom.orchestrators.report.orchestrator_report import (
    OrchestratorReport,
)
from connector.src.custom.orchestrators.threat_actor.orchestrator_threat_actor import (
    OrchestratorThreatActor,
)
from connector.src.octi.work_manager import WorkManager

LOG_PREFIX = "[Orchestrator]"


class Orchestrator:
    """Main orchestrator that delegates to specialized orchestrators."""

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
        self.logger.info(f"{LOG_PREFIX} Initializing orchestrator")

        if self.config.import_reports:
            self.logger.info(
                f"{LOG_PREFIX} Report import start date: {self.config.report_import_start_date}"
            )
            self.report_orchestrator = OrchestratorReport(
                work_manager, logger, config, tlp_level
            )
        if self.config.import_threat_actors:
            self.logger.info(
                f"{LOG_PREFIX} Threat actor import start date: {self.config.threat_actor_import_start_date}"
            )
            self.threat_actor_orchestrator = OrchestratorThreatActor(
                work_manager, logger, config, tlp_level
            )
        if self.config.import_malware_families:
            self.logger.info(
                f"{LOG_PREFIX} Malware family import start date: {self.config.malware_family_import_start_date}"
            )
            self.malware_orchestrator = OrchestratorMalware(
                work_manager, logger, config, tlp_level
            )
        self.logger.info(f"{LOG_PREFIX} Orchestrator initialized")

    async def run_report(self, initial_state: Optional[Dict[str, Any]]) -> None:
        """Run the report orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        self.logger.info(f"{LOG_PREFIX} Starting report orchestration")
        await self.report_orchestrator.run(initial_state)

    async def run_threat_actor(self, initial_state: Optional[Dict[str, Any]]) -> None:
        """Run the threat actor orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        self.logger.info(f"{LOG_PREFIX} Starting threat actor orchestration")
        await self.threat_actor_orchestrator.run(initial_state)

    async def run_malware_family(self, initial_state: Optional[Dict[str, Any]]) -> None:
        """Run the malware family orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        self.logger.info(f"{LOG_PREFIX} Starting malware family orchestration")
        await self.malware_orchestrator.run(initial_state)
