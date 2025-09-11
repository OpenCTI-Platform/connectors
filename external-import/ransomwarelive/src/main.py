import sys
import traceback

from pycti import OpenCTIConnectorHelper
from ransomwarelive.ransom_conn import RansomwareAPIConnector
from services.config_loader import RansomwareLiveConfig

if __name__ == "__main__":
    try:
        config = RansomwareLiveConfig()
        config_instance = config.load
        config_dict = config_instance.model_dump()
        helper = OpenCTIConnectorHelper(config=config_dict)
        connector = RansomwareAPIConnector(helper=helper, config=config_instance)
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
