import sys
import time
import traceback

from akamai_connector.connector import AkamaiConnector
from akamai_connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        # Load configuration using SDK
        settings = ConnectorSettings()

        # Initialize OpenCTI helper with SDK config
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        # Initialize connector with settings object
        # Using SDK-based configuration instead of manual environment parsing
        connector = AkamaiConnector(config=settings, helper=helper)

        connector.run()

    except Exception:
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)
