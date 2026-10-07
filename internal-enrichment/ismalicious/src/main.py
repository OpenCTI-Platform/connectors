"""Entry point for isMalicious OpenCTI connector."""

import traceback

from connector import ConnectorSettings, IsMaliciousConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        # Load configuration (environment variables, config.yml or .env)
        config = ConnectorSettings()

        # Initialize OpenCTI helper
        helper = OpenCTIConnectorHelper(
            config=config.to_helper_config(), playbook_compatible=True
        )

        # Create and run connector
        connector = IsMaliciousConnector(config, helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
