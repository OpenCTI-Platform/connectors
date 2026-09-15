import traceback

from connector import Connector, ConnectorSettings
from cortex_xdr_client import CortexXdrClient
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
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        client = CortexXdrClient(
            api_base_url=settings.pan_cortex_xdr_intel.api_base_url,
            api_key_id=settings.pan_cortex_xdr_intel.api_key_id,
            api_key=settings.pan_cortex_xdr_intel.api_key.get_secret_value(),
        )

        connector = Connector(helper=helper, settings=settings, client=client)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
