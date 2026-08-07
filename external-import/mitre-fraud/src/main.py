import traceback

from connector import ConnectorSettings, MitreFraud
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    """
    Entry point of the MITRE Fight Fraud (F3) connector.

    - traceback.print_exc(): prints the traceback of the exception to stderr.
    - exit(1): terminates the program signaling failure.
    """
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = MitreFraud(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
