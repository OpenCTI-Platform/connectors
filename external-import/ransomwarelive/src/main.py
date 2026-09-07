import sys
import traceback

from pycti import OpenCTIConnectorHelper
from ransomwarelive.ransom_conn import RansomwareAPIConnector
from ransomwarelive.settings import ConnectorSettings

if __name__ == "__main__":
    try:
        config = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=config.to_helper_config())
        connector = RansomwareAPIConnector(helper=helper, config=config)
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
