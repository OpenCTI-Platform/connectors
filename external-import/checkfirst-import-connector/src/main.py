import traceback

from connector import CheckfirstImportConnector, ConnectorSettings
from pycti import OpenCTIConnectorHelper
from utils.file_logging import attach_file_logging

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
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        # After helper/SDK logging setup (those may replace root handlers).
        if settings.checkfirst.log_file:
            log_path = attach_file_logging(
                settings.checkfirst.log_file,
                settings.connector.log_level,
            )
            helper.connector_logger.info(
                "[CONNECTOR] File logging enabled",
                {"log_file": str(log_path)},
            )

        connector = CheckfirstImportConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
