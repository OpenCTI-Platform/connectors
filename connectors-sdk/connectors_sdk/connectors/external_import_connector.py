"""External import connector's default class covering most of use cases.
Can be used as-is (this is not an abstract class) or subclassed to fit specific needs.

Architecture:
- ExternalImportConnector: Listen to the scheduler and orchestrate the workflow (entrypoint)
- Config: Parse and validate connector's config files
- OpenCTIConnectorHelper: Communicate with OpenCTI platform
- StateManager: Load, validate and save connector's state
- DataProcessors: Collect, transform and send intelligence data to OpenCTI
"""

import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from connectors_sdk.logger.sdk_logger import sdk_logger as logger

if TYPE_CHECKING:
    from connectors_sdk.connectors.base_data_processor import BaseDataProcessor
    from connectors_sdk.settings.base_settings import BaseConnectorSettings
    from connectors_sdk.state_manager.base_state_manager import (
        BaseConnectorStateManager,
    )
    from pycti import OpenCTIConnectorHelper


class ExternalImportConnector:
    """External import connector orchestrator.

    Orchestrates the workflow without implementing business logic.
    Delegates the business logic to the data processors injected as dependencies.
    Can be used as-is (this is not an abstract class) or subclassed to fit specific needs.

    Responsibilities:
    - Orchestrate connector lifecycle (start, callback)
    - Wire up data processors
    - Ensure high-level error handling (keep connector alive)
    - Provide consistent logging

    NOT responsible for:
    - State management details (StateManager)
    - Intelligence collection (DataProcessors)
    - Work management details (WorkManager)
    """

    def __init__(
        self,
        config: "BaseConnectorSettings",
        helper: "OpenCTIConnectorHelper",
        state_manager: "BaseConnectorStateManager",
        data_processors: list["BaseDataProcessor"],
    ) -> None:
        """Initialize connector with config and helper."""
        self.config = config
        self.helper = helper
        self.state_manager = state_manager
        self.data_processors = data_processors

        # Ensure OpenCTIConnectorHelper's logger is attached to SDK's logger as soon as it's reachable
        logger.attach_connector_helper_logger(self.helper)
        self._logger = logger.get_child("connector")

        self._logger.debug(f"{self.__class__.__name__} initialized succesfully")

    def callback(self) -> None:
        """Main processing function.
        Standard workflow for all connectors:
            1. Load state
            2. Collect data, transform it and send it to OpenCTI
            3. Update state
        The global error handling ensures that the connector keeps alive in case of unexpected errors.
        """
        try:
            self._logger.info(
                "Starting connector's run...",
                {"connector_name": self.config.connector.name},
            )

            now = datetime.now(timezone.utc)

            # 1. Load state
            self.state_manager.load()

            # 2. Collect data, transform it and send it to OpenCTI
            for data_processor in self.data_processors:
                collected_data = data_processor.collect()
                stix_objects = data_processor.transform(collected_data)
                data_processor.send(stix_objects)

            # 3. Update state
            self.state_manager.last_run = now
            self.state_manager.save()

            self._logger.info(
                "Connector's run completed",
                {"connector_name": self.config.connector.name},
            )
        except (KeyboardInterrupt, SystemExit):
            self._logger.info(
                "Connector stopped...",
                {"connector_name": self.config.connector.name},
            )
            sys.exit(0)
        except Exception as err:
            self._logger.error(
                "Unexpected error occurred",
                {"connector_name": self.config.connector.name, "error": str(err)},
            )

    def start(self) -> None:
        """Schedule callback based on connector's configuration."""
        self.helper.schedule_iso(
            message_callback=self.callback,
            duration_period=self.config.connector.duration_period,  # type: ignore
        )
