import traceback

from pycti import OpenCTIConnectorHelper
from teamt5 import TeamT5Connector
from teamt5.config_loader import ConfigConnector

if __name__ == "__main__":

    try:
        config = ConfigConnector()
        helper = OpenCTIConnectorHelper(config=config.load)

        connector = TeamT5Connector(config=config, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
