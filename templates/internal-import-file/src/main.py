import traceback

from internal_import_file_connector import ConnectorTemplate
from internal_import_file_connector.config_loader import ConfigConnector
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
        config = ConfigConnector()
        helper = OpenCTIConnectorHelper(config=config.load)

        connector = ConnectorTemplate(config=config, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
