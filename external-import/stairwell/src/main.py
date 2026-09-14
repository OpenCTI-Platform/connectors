import traceback

from pycti import OpenCTIConnectorHelper

from connector.connector import StairwellImportConnector
from connector.settings import ConnectorSettings

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = StairwellImportConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
