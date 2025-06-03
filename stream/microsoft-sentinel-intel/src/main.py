import traceback

from microsoft_sentinel_intel_connector import MicrosoftSentinelIntelConnector
from microsoft_sentinel_intel_connector.api_handler import SentinelApiHandler
from microsoft_sentinel_intel_connector.config import ConnectorSettings
from pycti import OpenCTIConnectorHelper


def main() -> None:
    """
    Entry point of the script

    - traceback.print_exc(): This function prints the traceback of the exception to the standard error (stderr).
    The traceback includes information about the point in the program where the exception occurred,
    which is very useful for debugging purposes.
    - exit(1): effective way to terminate a Python program when an error is encountered.
    It signals to the operating system and any calling processes that the program did not complete successfully.
    """
    config = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config=config.model_dump_pycti())
    client = SentinelApiHandler(helper, config)

    connector = MicrosoftSentinelIntelConnector(
        config=config, helper=helper, client=client
    )
    connector.run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        exit(1)
