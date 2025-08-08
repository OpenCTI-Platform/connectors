import traceback

from pycti import OpenCTIConnectorHelper
from connector import ConfigLoader, GreyNoiseFeedConnector

if __name__ == "__main__":
    try:
        config = ConfigLoader()
        helper = OpenCTIConnectorHelper(config=config.model_dump_pycti())

        connector = GreyNoiseFeedConnector(config, helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
