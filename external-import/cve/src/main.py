"""OpenCTI CVE connector main module"""

import traceback

from pycti import OpenCTIConnectorHelper
from connector import CVEConnector
from services.utils import ConfigLoader

if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        config = ConfigLoader()
        helper = OpenCTIConnectorHelper(config.model_dump(exclude_none=True))
        
        connector = CVEConnector(config, helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
