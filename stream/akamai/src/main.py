import sys
import time
import traceback

from pycti import OpenCTIConnectorHelper
from akamai_connector.connector import AkamaiConnector
from settings import get_config


if __name__ == "__main__":
    try:
        # Initialize OpenCTI helper
        # This automatically loads OpenCTI-related environment variables

        helper = OpenCTIConnectorHelper({})

        # Load connector configuration
        # Configuration is centralized in settings.py for maintainability
        config = get_config(helper)

        # Instantiate the Akamai connector with the loaded configuration
        # Using **config allows flexible and clean parameter passing
        connector = AkamaiConnector(
            helper=helper,
            **config
        )

        # Start the connector
        # This will listen to the OpenCTI live stream and process events
        connector.run()

    except Exception:
        
        traceback.print_exc()

        # Small delay before exit to avoid crash loops in container environments
        time.sleep(10)

        sys.exit(1)