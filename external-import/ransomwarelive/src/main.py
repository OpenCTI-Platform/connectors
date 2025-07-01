import sys
import traceback

from lib.ransom_conn import RansomwareAPIConnector
from pycti import OpenCTIConnectorHelper

from ransomwarelive.config import ConnectorSettings

if __name__ == "__main__":
    try:
        config = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=config.model_dump_pycti())
        connector = RansomwareAPIConnector(helper=helper, config=config)
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
