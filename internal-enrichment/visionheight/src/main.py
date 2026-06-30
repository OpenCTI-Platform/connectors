import traceback

from connector import ConnectorSettings, VisionHeightConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    """
    Entry point of the script.

    - traceback.print_exc(): prints the exception traceback to stderr for debugging.
    - exit(1): signals to the OS that the program did not complete successfully.
    """
    try:
        settings = ConnectorSettings()

        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(),
            playbook_compatible=True,  # required: connector returns a STIX bundle
        )

        connector = VisionHeightConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
