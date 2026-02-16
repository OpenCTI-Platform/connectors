"""Orchestrator for fetching and processing data.

This orchestrator handles the fetching, conversion, and processing data
using the proper fetchers/converters/batch processor pattern.
"""

import logging
from typing import Any

from connector.src.custom.configs import GTIConfig
from connector.src.custom.orchestrators.campaign.orchestrator_campaign import (
    OrchestratorCampaign,
)
from connector.src.custom.orchestrators.malware.orchestrator_malware import (
    OrchestratorMalware,
)
from connector.src.custom.orchestrators.report.orchestrator_report import (
    OrchestratorReport,
)
from connector.src.custom.orchestrators.threat_actor.orchestrator_threat_actor import (
    OrchestratorThreatActor,
)
from connector.src.custom.orchestrators.vulnerability.orchestrator_vulnerability import (
    OrchestratorVulnerability,
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

        self.logger.info(
            "API URL",
            {"prefix": LOG_PREFIX, "api_url": self.config.api_url.unicode_string()},
        )
        self.logger.info("Initializing orchestrator", {"prefix": LOG_PREFIX})

        if self.config.import_reports:
            self.logger.info(
                "Report import start date",
                {
                    "prefix": LOG_PREFIX,
                    "start_date": self.config.report_import_start_date,
                },
            )
            self.report_orchestrator = OrchestratorReport(
                work_manager, logger, config, tlp_level
            )
        if self.config.import_threat_actors:
            self.logger.info(
                "Threat actor import start date",
                {
                    "prefix": LOG_PREFIX,
                    "start_date": self.config.threat_actor_import_start_date,
                },
            )
            self.threat_actor_orchestrator = OrchestratorThreatActor(
                work_manager, logger, config, tlp_level
            )
        if self.config.import_campaigns:
            self.logger.info(
                "Campaign import start date",
                {
                    "prefix": LOG_PREFIX,
                    "start_date": self.config.campaign_import_start_date,
                },
            )
            self.campaign_orchestrator = OrchestratorCampaign(
                work_manager, logger, config, tlp_level
            )
        if self.config.import_malware_families:
            self.logger.info(
                "Malware family import start date",
                {
                    "prefix": LOG_PREFIX,
                    "start_date": self.config.malware_family_import_start_date,
                },
            )
            self.malware_orchestrator = OrchestratorMalware(
                work_manager, logger, config, tlp_level
            )
        if self.config.import_vulnerabilities:
            self.logger.info(
                "Vulnerability import start date",
                {
                    "prefix": LOG_PREFIX,
                    "start_date": self.config.vulnerability_import_start_date,
                },
            )
            self.vulnerability_orchestrator = OrchestratorVulnerability(
                work_manager, logger, config, tlp_level
            )
            self.logger.info("Orchestrator initialized", {"prefix": LOG_PREFIX})

    async def run_report(self, initial_state: dict[str, Any] | None) -> None:
        """Run the report orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        self.logger.info("Starting report orchestration", {"prefix": LOG_PREFIX})
        await self.report_orchestrator.run(initial_state)

    async def run_threat_actor(self, initial_state: dict[str, Any] | None) -> None:
        """Run the threat actor orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        self.logger.info("Starting threat actor orchestration", {"prefix": LOG_PREFIX})
        await self.threat_actor_orchestrator.run(initial_state)

    async def run_campaign(self, initial_state: dict[str, Any] | None) -> None:
        """Run the campaign orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        self.logger.info("Starting campaign orchestration", {"prefix": LOG_PREFIX})
        await self.campaign_orchestrator.run(initial_state)

    async def run_malware_family(self, initial_state: dict[str, Any] | None) -> None:
        """Run the malware family orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        self.logger.info(
            "Starting malware family orchestration", {"prefix": LOG_PREFIX}
        )
        await self.malware_orchestrator.run(initial_state)

    async def run_vulnerability(self, initial_state: dict[str, Any] | None) -> None:
        """Run the vulnerability orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        self.logger.info("Starting vulnerability orchestration", {"prefix": LOG_PREFIX})
        await self.vulnerability_orchestrator.run(initial_state)
