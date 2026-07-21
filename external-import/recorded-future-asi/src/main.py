"""
Entry point of the connector script.

On failure, traceback is printed to stderr and the process exits with status 1.
"""

import sys
import traceback

from connector import ConnectorSettings, RecordedFutureAsiConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = RecordedFutureAsiConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
