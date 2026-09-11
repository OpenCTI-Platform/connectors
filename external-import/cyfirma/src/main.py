import traceback

from connector import ConnectorSettings, CyfirmaConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = CyfirmaConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
