import sys

from checkfirst_dataset.main_logic import run_once
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class CheckfirstImportConnector:
    """Minimal external-import connector implementation.

    This follows the standard external-import connector template:
    - `process_message()` does one ingestion pass
    - `run()` schedules runs via `OpenCTIConnectorHelper.schedule_process()`

    The actual API ingestion + STIX mapping is implemented under
    `checkfirst_dataset/` and reused here.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

    def process_message(self) -> None:
        """One connector run: fetch API data and push bundles to OpenCTI."""
        try:
            run_once(self.helper, self.config)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """Start the connector using the standard scheduler."""
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
