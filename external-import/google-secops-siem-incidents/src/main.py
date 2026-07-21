"""Entrypoint for the Google SecOps external-import connector."""

import sys
import traceback

from google_secops_siem_incidents import ConnectorSettings, GoogleSecOpsConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
        connector = GoogleSecOpsConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
