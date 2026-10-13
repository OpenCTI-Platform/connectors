"""Lab539 AiTM Feed OpenCTI Connector entry point."""

import sys
import traceback

from lab539_aitm_connector.connector import Lab539AiTMConnector
from lab539_aitm_connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
        connector = Lab539AiTMConnector(config=settings, helper=helper)
        connector.run()
    except Exception:  # pylint: disable=broad-exception-caught
        traceback.print_exc()
        sys.exit(1)
