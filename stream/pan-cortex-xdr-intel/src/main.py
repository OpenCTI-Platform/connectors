import traceback

from connector import Connector
from cortex_xdr_client import CortexXdrClient

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
        # TODO: settings = ConnectorSettings()
        settings = None
        # TODO: helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
        helper = None
        # TODO: configure the client from `settings` instead of placeholders
        client = CortexXdrClient(
            api_base_url="https://ChangeMe", api_key_id="", api_key=""
        )

        connector = Connector(helper=helper, settings=settings, client=client)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
