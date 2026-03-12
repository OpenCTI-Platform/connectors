"""
USTA Prodaft OpenCTI External Import Connector - Entry Point.

This is the main entry point for the connector.  It initializes
the Pydantic settings, the OpenCTI helper, and starts the connector.
"""

import traceback

from connector import ConnectorSettings, UstaProdaftConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = UstaProdaftConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
