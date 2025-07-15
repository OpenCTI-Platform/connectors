import traceback

from pycti import OpenCTIConnectorHelper
from TeamT5_external_import import TeamT5Connector
from TeamT5_external_import.config_loader import ConfigConnector

if __name__ == "__main__":

    try:
        config = ConfigConnector()
        helper = OpenCTIConnectorHelper(config=config.load)

        connector = TeamT5Connector(config=config, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
