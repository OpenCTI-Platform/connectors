import traceback

from connector import ConfigLoader, SikkerAPIConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        config = ConfigLoader()
        helper = OpenCTIConnectorHelper(config=config.to_pycti_config())

        connector = SikkerAPIConnector(config, helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
