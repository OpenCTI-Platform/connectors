import traceback

from connector import ConnectorSettings, VulnersConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    """
    Entry point of the connector.

    - traceback.print_exc(): prints the traceback of the exception to stderr,
      which is very useful for debugging purposes.
    - exit(1): signals to the operating system and any calling processes that
      the program did not complete successfully.
    """
    try:
        settings = ConnectorSettings()

        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(),
            playbook_compatible=True,  # a STIX bundle is always sent back
        )

        connector = VulnersConnector(helper=helper, settings=settings)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
