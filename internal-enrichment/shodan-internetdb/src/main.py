"""
Entry point of the script

- traceback.print_exc(): This function prints the traceback of the exception to the standard error (stderr).
The traceback includes information about the point in the program where the exception occurred,
which is very useful for debugging purposes.
- exit(1): effective way to terminate a Python program when an error is encountered.
It signals to the operating system and any calling processes that the program did not complete successfully.
"""

import sys
import traceback

from pycti import OpenCTIConnectorHelper
from shodan_internetdb.config import ConfigConnector
from shodan_internetdb.connector import ShodanInternetDBConnector

if __name__ == "__main__":
    try:
        config = ConfigConnector()
        helper = OpenCTIConnectorHelper(config.load, True)

        connector = ShodanInternetDBConnector(helper=helper, config=config)
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
