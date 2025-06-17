import traceback

from pycti import OpenCTIConnectorHelper
from src.connector import ConnectorServicenow
from src.connector.services.config_loader import ServiceNowConfig

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
        config = ServiceNowConfig()
        config_instance = config.load
        # Convert the config into a dictionary, automatically excluding any parameters set to `None`.
        config_dict = config_instance.model_dump(exclude_none=True)
        helper = OpenCTIConnectorHelper(config=config_dict)
        connector = ConnectorServicenow(config_instance, helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
