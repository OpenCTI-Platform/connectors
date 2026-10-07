"""Rösti connector entry point.

Loads the configuration and the persisted state, then starts the
connectors-sdk scheduler, which runs ``ReportsProcessor`` every
``CONNECTOR_DURATION_PERIOD``.
"""

import sys
import traceback

from connector import ConnectorSettings, ConnectorState
from connector.data_processors import ReportsProcessor
from connectors_sdk import ExternalImportConnector

if __name__ == "__main__":
    try:
        connector = ExternalImportConnector(
            settings=ConnectorSettings(),
            state=ConnectorState(),
            data_processors=[ReportsProcessor()],
        )
        connector.start()
    except Exception:  # pylint: disable=broad-exception-caught
        traceback.print_exc()
        sys.exit(1)
