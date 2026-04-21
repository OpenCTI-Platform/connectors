import traceback

from connector import BitSightConnector, ConnectorSettings
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = BitSightConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)

