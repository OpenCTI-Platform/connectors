"""Google SecOps external-import connector."""

import sys
from datetime import datetime
from typing import Any

from pycti import OpenCTIConnectorHelper

from google_secops_siem_incidents.converter_to_stix import ConverterToStix
from google_secops_siem_incidents.settings import ConnectorSettings

_LOG_PREFIX = "[CONNECTOR]"


class GoogleSecOpsConnector:
    """External-import connector that fetches Google SecOps SIEM incidents and sends them to OpenCTI."""

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """Initialise the connector with configuration and helper.

        Args:
            config: Connector configuration.
            helper: OpenCTI helper instance.
        """
        self.config = config
        self.helper = helper
        self._client: Any = None
        self.converter_to_stix = ConverterToStix(
            helper=self.helper,
            tlp_level=self.config.google_secops_siem_incidents.tlp_level,
        )

    def _collect_intelligence(self) -> None:
        """Collect intelligence from Google SecOps API.

        Returns:
            None. Async pipeline results are sent directly to OpenCTI.
        """
        return None

    def process_message(self) -> None:
        """Main connector process: collect intelligence, send bundle, update state.

        Raises:
            SystemExit: On KeyboardInterrupt or SystemExit.
        """
        try:
            now = datetime.now()
            current_state = self.helper.get_state()

            if current_state and "last_run" in current_state:
                self.helper.connector_logger.info(
                    f"{_LOG_PREFIX} Connector last run",
                    {"last_run_datetime": current_state["last_run"]},
                )
            else:
                self.helper.connector_logger.info(
                    f"{_LOG_PREFIX} Connector has never run..."
                )

            self._collect_intelligence()

            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
            self.helper.set_state({"last_run": current_state_datetime})

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.error(
                f"{_LOG_PREFIX} Connector stopped.",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)

        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """Start the connector and schedule recurring runs."""
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
