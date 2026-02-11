from __future__ import annotations

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
        from checkfirst_dataset.main_logic import run_once

        run_once(self.helper, self.config)

    def run(self) -> None:
        """Start the connector in `once` or `loop` mode."""
        if self.config.checkfirst.run_mode == "once":
            self.process_message()
            return

        # Loop mode: use schedule_iso for backpressure
        total_secs = int(self.config.connector.duration_period.total_seconds())
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=f"PT{total_secs}S",
        )
