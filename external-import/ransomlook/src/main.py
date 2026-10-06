# pylint: disable=wrong-import-order

import sys
import traceback

from connector import ConnectorSettings, RansomLookConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
        RansomLookConnector(settings, helper).run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
