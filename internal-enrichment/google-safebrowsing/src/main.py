import traceback

from connector import ConnectorSettings, SafeBrowsingConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    """Entry point of the connector."""
    try:
        settings = ConnectorSettings()
        # Not playbook compatible: no bundle is sent when there is no match
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = SafeBrowsingConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
