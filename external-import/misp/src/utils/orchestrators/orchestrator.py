"""Orchestrator for fetching and processing data.

This orchestrator handles the fetching, conversion, and processing data
using the proper fetchers/converters/batch processor pattern.
"""

from typing import TYPE_CHECKING, Any

from utils.orchestrators.orchestrator_event import OrchestratorEvent

if TYPE_CHECKING:
    from connector.settings import MispConfig
    from utils.protocols import LoggerProtocol
    from utils.work_manager import WorkManager

LOG_PREFIX = "[Orchestrator]"


class Orchestrator:
    """Main orchestrator that delegates to specialized orchestrators."""

    def __init__(
        self,
        work_manager: "WorkManager",
        logger: "LoggerProtocol",
        config: "MispConfig",
    ) -> None:
        """Initialize the Orchestrator.

        Args:
            work_manager: Work manager for handling OpenCTI work operations
            logger: Logger instance for logging
            config: Configuration object containing connector settings

        """
        self.work_manager = work_manager
        self.logger = logger
        self.config = config

        self.logger.info(
            "MISP URL",
            {"prefix": LOG_PREFIX, "url": self.config.url.unicode_string()},
        )
        self.logger.info("Initializing orchestrator", {"prefix": LOG_PREFIX})

        self.logger.info(
            "Report import start date",
            {
                "prefix": LOG_PREFIX,
                "start_date": self.config.import_from_date,
            },
        )
        self.event_orchestrator = OrchestratorEvent(work_manager, logger, config)
        self.logger.info("Orchestrator initialized", {"prefix": LOG_PREFIX})

    def run_event(self, initial_state: dict[str, Any] | None) -> None:
        """Run the event orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        self.logger.info("Starting MISP event orchestration", {"prefix": LOG_PREFIX})
        self.event_orchestrator.run(initial_state)
