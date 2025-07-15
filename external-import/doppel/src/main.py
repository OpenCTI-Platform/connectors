import traceback

from external_import_connector.config_loader import ConfigDoppel
from external_import_connector.connector import DoppelConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        config = ConfigDoppel()
        helper = OpenCTIConnectorHelper(config=config.load)
        connector = DoppelConnector(config=config, helper=helper)
        connector.run()

    except ValueError as ve:
        print(f"[Config Error] {ve}")
        exit(1)

    except Exception:
        traceback.print_exc()
        exit(1)
