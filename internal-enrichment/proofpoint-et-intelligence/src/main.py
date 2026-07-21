import traceback

from connector import ConnectorSettings, ProofpointEtIntelligenceConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    """Entry point of the connector."""
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(), playbook_compatible=True
        )

        connector = ProofpointEtIntelligenceConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
