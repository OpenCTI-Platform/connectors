import traceback

from connector import ConnectorSettings, RedpandaConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    """
    Entry point of the script.

    - traceback.print_exc(): prints the traceback of the exception to stderr,
      which is very useful for debugging purposes.
    - exit(1): terminates the program signalling that it did not complete
      successfully.
    """
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = RedpandaConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
