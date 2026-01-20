import traceback

from pycti import OpenCTIConnectorHelper

from teamt5_connector import TeamT5Connector
from teamt5_connector.settings import ConnectorSettings

if __name__ == "__main__":

    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = TeamT5Connector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
