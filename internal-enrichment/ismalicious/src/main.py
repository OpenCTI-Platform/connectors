"""Entry point for isMalicious OpenCTI connector."""

import traceback

from pycti import OpenCTIConnectorHelper

from connector import ConfigLoader, IsMaliciousConnector

if __name__ == "__main__":
    try:
        # Load configuration from environment
        config = ConfigLoader.from_env()

        # Initialize OpenCTI helper
        helper = OpenCTIConnectorHelper(
            {
                "id": config.connector.id,
                "type": config.connector.type,
                "name": config.connector.name,
                "scope": config.connector.scope,
                "log_level": config.connector.log_level,
                "auto": config.connector.auto,
            }
        )

        # Create and run connector
        connector = IsMaliciousConnector(config, helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
