"""OpenCTI Splunk connector entry point."""

import traceback

from pycti import OpenCTIConnectorHelper
from splunk_connector import ConnectorSettings, SplunkConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = SplunkConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
