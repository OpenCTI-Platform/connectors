import sys
import time
import traceback

from pycti import OpenCTIConnectorHelper

from connector.connector import RSTThreatLibrary
from connector.settings import ConnectorSettings

__all__ = ["RSTThreatLibrary"]


if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
        connector = RSTThreatLibrary(config=settings, helper=helper)
        connector.run()
    except Exception as ex:
        print(str(ex))
        traceback.print_tb(ex.__traceback__)
        time.sleep(10)
        sys.exit(0)
