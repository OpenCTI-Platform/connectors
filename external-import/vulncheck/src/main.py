import sys
import traceback

from connector import ConnectorSettings, ConnectorVulnCheck
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        config = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=config.to_helper_config())
        connector = ConnectorVulnCheck(config=config, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
