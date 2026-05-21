import sys
import traceback

from connector import ConnectorSettings, MoknConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    """
    Entry point of the script.
    :return: None
    """
    try:
        config = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=config.to_helper_config())

        connector = MoknConnector(config=config, helper=helper)
        connector.run()
    except Exception:  # pylint: disable=broad-exception-caught
        traceback.print_exc()
        sys.exit(1)
