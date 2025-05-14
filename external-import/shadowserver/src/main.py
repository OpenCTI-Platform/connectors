import traceback

from pycti import OpenCTIConnectorHelper
from shadowserver.config import ConnectorSettings
from shadowserver.connector import CustomConnector

if __name__ == "__main__":
    try:
        config = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=config.model_dump_pycti())
        connector = CustomConnector(helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
