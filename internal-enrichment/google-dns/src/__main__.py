import traceback

from pycti import OpenCTIConnectorHelper
from src.connector.config_loader import GoogleDNSConfig
from src.connector.connector import GoogleDNSConnector

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
        config = GoogleDNSConfig()
        config_instance = config.load
        # playbook_compatible=True only if a bundle is sent !
        helper = OpenCTIConnectorHelper(
            config=config_instance.model_dump(exclude_none=True),
            playbook_compatible=True,
        )

        connector = GoogleDNSConnector(config=config, helper=helper)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
