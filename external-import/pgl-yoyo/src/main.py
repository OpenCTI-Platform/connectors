import traceback

from pycti import OpenCTIConnectorHelper

from pgl_yoyo.config_loader import ConfigConnector
from pgl_yoyo.pgl_connector import PGLConnector

if __name__ == "__main__":
    try:
        config = ConfigConnector()
        helper = OpenCTIConnectorHelper(config=config.load)

        connector = PGLConnector(config=config, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
