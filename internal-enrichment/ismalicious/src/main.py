"""Entry point for isMalicious OpenCTI connector."""

import traceback

from pycti import OpenCTIConnectorHelper

from connector import IsMaliciousConnector, ConfigLoader

if __name__ == "__main__":
    """
    Entry point of the script.
    
    traceback.print_exc(): This function prints the traceback of the exception 
    to the standard error (stderr). The traceback includes information about 
    the point in the program where the exception occurred, which is very useful 
    for debugging purposes.
    
    exit(1): Effective way to terminate a Python program when an error is 
    encountered. It signals to the operating system and any calling processes 
    that the program did not complete successfully.
    """
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
