"""
Entry point of the script

- traceback.print_exc(): This function prints the traceback of the exception to the standard error (stderr).
The traceback includes information about the point in the program where the exception occurred,
which is very useful for debugging purposes.
- exit(1): effective way to terminate a Python program when an error is encountered.
It signals to the operating system and any calling processes that the program did not complete successfully.
"""

import traceback

from connector import (
    ConnectorSettings,
    ConnectorStateManager,
    ReportProcessor,
)
from connectors_sdk import ExternalImportConnector as PouetPouetConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
        state_manager = ConnectorStateManager(helper=helper)  # type: ignore[abstract]

        report_processor = ReportProcessor(
            config=settings,
            helper=helper,
            state_manager=state_manager,
        )

        connector = PouetPouetConnector(
            config=settings,
            helper=helper,
            state_manager=state_manager,
            data_processor=report_processor,
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
