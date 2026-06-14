import traceback

from connector import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from thehive import TheHive

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = TheHive(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
