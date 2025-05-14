import traceback

from pycti import OpenCTIConnectorHelper
from shadowserver.connector import CustomConnector

if __name__ == "__main__":
    try:
        helper = OpenCTIConnectorHelper({})
        connector = CustomConnector(helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
