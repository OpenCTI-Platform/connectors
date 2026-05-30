"""
USTA OpenCTI External Import Connector - Entry Point.

This is the main entry point for the connector.  It initializes
the Pydantic settings, the OpenCTI helper, and starts the connector.
"""

import sys
import traceback

from connector import ConnectorSettings, UstaConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = UstaConnector(config=settings, helper=helper)
        connector.run()
    except Exception:  # pylint: disable=broad-exception-caught
        traceback.print_exc()
        sys.exit(1)
