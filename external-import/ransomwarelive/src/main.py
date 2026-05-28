import sys
import traceback

from models import ConfigLoader
from pycti import OpenCTIConnectorHelper
from ransomwarelive.ransom_conn import RansomwareAPIConnector

if __name__ == "__main__":
    try:
        config = ConfigLoader()
        helper = OpenCTIConnectorHelper(config=config.model_dump_pycti())
        connector = RansomwareAPIConnector(helper=helper, config=config)
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
