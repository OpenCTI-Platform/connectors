"""
RansomFeed Connector
Entry point for the RansomFeed external import connector
"""
import sys
import traceback

from pycti import OpenCTIConnectorHelper
from ransomfeed.config_loader import ConfigLoader
from ransomfeed.connector import RansomFeedConnector


if __name__ == "__main__":
    """
    Entry point of the connector
    """
    try:
        # Load configuration
        config = ConfigLoader()
        
        # Initialize OpenCTI connector helper
        helper = OpenCTIConnectorHelper(config=config.load)
        
        # Initialize and run the connector
        connector = RansomFeedConnector(helper=helper, config=config)
        connector.run()
        
    except Exception:
        traceback.print_exc()
        sys.exit(1)
