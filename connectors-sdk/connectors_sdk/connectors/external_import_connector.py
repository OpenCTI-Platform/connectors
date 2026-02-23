"""External import connector's default class covering most of use cases.
Can be used as-is (this is not an abstract class) or subclassed to fit specific needs.

Architecture:
- ExternalImportConnector: Listen to the scheduler and orchestrate the workflow (entrypoint)
- Config: Parse and validate connector's config files
- OpenCTIConnectorHelper: Communicate with OpenCTI platform
- StateManager: Load, validate and save connector's state
- DataProcessor: Collect, transform and send intelligence data to OpenCTI
"""

import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING

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
    - Intelligence collection (DataProcessor)
    - Work management details (WorkManager)
    """

    def __init__(
        self,
        config: "BaseConnectorSettings",
        helper: "OpenCTIConnectorHelper",
        state_manager: "BaseConnectorStateManager",
        data_processor: "BaseDataProcessor",
    ) -> None:
        """Initialize connector with config and helper."""
        self.config = config
        self.helper = helper
        self.logger = helper.connector_logger
        self.state_manager = state_manager
        self.data_processor = data_processor

    def callback(self) -> None:
        """Main processing function.
        Standard workflow for all connectors:
            1. Load state
            2. Collect data, transform it and send it to OpenCTI
            3. Update state
        The global error handling ensures that the connector keeps alive in case of unexpected errors.
        """
        try:
            self.logger.info(
                "[CONNECTOR] Starting connector...",
                {"connector_name": self.config.connector.name},
            )
            now = datetime.now(timezone.utc)

            # 1. Load state
            self.state_manager.load()
            self.logger.debug(
                "[CONNECTOR] Current connector's state",
                {"state": self.state_manager.model_dump()},
            )

            # 2. Collect data, transform it and send it to OpenCTI
            collected_data = self.data_processor.collect()
            stix_objects = self.data_processor.transform(collected_data)
            self.data_processor.send(stix_objects)

            # 3. Update state
            self.state_manager.last_run = now
            self.state_manager.save()

            self.logger.info(
                "[CONNECTOR] Connector's run completed",
                {"connector_name": self.config.connector.name},
            )
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.config.connector.name},
            )
            sys.exit(0)
        except Exception as err:
            self.logger.error(err, {"connector": self.config.connector.name})

    def start(self) -> None:
        """Schedule callback based on connector's configuration."""
        self.helper.schedule_iso(
            message_callback=self.callback,
            duration_period=self.config.connector.duration_period,  # type: ignore
        )
