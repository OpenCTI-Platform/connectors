import traceback

from connector import ConnectorSettings, DoppelConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()

        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(),
            playbook_compatible=True,  # ! `playbook_compatible=True` only if a bundle is sent
        )

        connector = DoppelConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
