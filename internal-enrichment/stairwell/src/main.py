import traceback

from pycti import OpenCTIConnectorHelper

from connector.connector import StairwellConnector
from connector.settings import ConnectorSettings

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(),
            playbook_compatible=True,  # a STIX bundle is always sent back
        )

        connector = StairwellConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
