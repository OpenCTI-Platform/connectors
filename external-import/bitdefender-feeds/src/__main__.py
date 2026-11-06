import traceback

from pycti import OpenCTIConnectorHelper
from src.bitdefender_import_feed.connector import BitdefenderFeedConnector
from src.bitdefender_import_feed.settings import ConnectorSettings

if __name__ == "__main__":
    try:
        config = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=config.to_helper_config())
        connector = BitdefenderFeedConnector(config=config, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        raise
