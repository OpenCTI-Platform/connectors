from __future__ import annotations

from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class CheckfirstImportConnector:
    """Minimal external-import connector implementation.

    This follows the standard external-import connector template:
    - `process_message()` does one ingestion pass
    - `run()` schedules runs via `OpenCTIConnectorHelper.schedule_process()`

    The actual dataset parsing + STIX mapping is implemented under
    `checkfirst_dataset/` and reused here.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

    def process_message(self) -> None:
        """One connector run: ingest files and push bundles to OpenCTI."""
        from checkfirst_dataset.main_logic import run_once

        run_once(self.helper, self.config)

    def run(self) -> None:
        """Start the connector in `once` or `loop` mode."""
        if self.config.checkfirst.run_mode == "loop":
            self.process_message()
            return

        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
