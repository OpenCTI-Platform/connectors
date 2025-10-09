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

from censys_enrichment.client import Client
from censys_enrichment.config import Config as ConfigLoader
from censys_enrichment.connector import Connector
from censys_enrichment.converter import Converter
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        config = ConfigLoader()
        helper = OpenCTIConnectorHelper(
            config=config.to_helper_config(),
            playbook_compatible=True,
        )
        client = Client(
            organisation_id=config.censys_enrichment.organisation_id.get_secret_value(),
            token=config.censys_enrichment.token.get_secret_value(),
        )
        converter = Converter()
        connector = Connector(
            config=config,
            helper=helper,
            client=client,
            converter=converter,
        )
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
