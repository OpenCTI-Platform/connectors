import traceback

from doppel.config_loader import ConfigDoppel
from doppel.connector import DoppelConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        config = ConfigDoppel()
        helper = OpenCTIConnectorHelper(config=config.load)
        connector = DoppelConnector(config=config, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
