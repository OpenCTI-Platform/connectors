import traceback

from connector import ConnectorSettings, ModatConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        config = ConnectorSettings()
        helper = OpenCTIConnectorHelper(
            config=config.to_helper_config(),
            playbook_compatible=True,
        )
        connector = ModatConnector(config=config, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
