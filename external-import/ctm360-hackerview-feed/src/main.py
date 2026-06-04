import sys
import traceback

from connector import ConnectorSettings, CTM360HackerViewConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(),
        )
        connector = CTM360HackerViewConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
