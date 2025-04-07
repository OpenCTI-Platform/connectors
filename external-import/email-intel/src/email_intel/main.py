import traceback

from email_intel.client import Client
from email_intel.config import ConnectorConfig
from email_intel.connector import Connector
from email_intel.converter import ConnectorConverter
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    """
    Entry point of the script

    - traceback.print_exc(): This function prints the traceback of the exception to the standard error (stderr).
    The traceback includes information about the point in the program where the exception occurred,
    which is very useful for debugging purposes.
    - exit(1): effective way to terminate a Python program when an error is encountered.
    It signals to the operating system and any calling processes that the program did not complete successfully.
    """
    try:
        config = ConnectorConfig()
        helper = OpenCTIConnectorHelper(config=config.model_dump(mode="json"))
        converter = ConnectorConverter(helper=helper, config=config)
        client = Client(helper=helper, config=config)

        connector = Connector(
            config=config,
            helper=helper,
            converter=converter,
            client=client,
        )

        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
