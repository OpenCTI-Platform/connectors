import traceback

from connector import ConnectorSettings, SpurIPProcessor
from connectors_sdk import InternalEnrichmentConnector

if __name__ == "__main__":
    """
    Entry point of the script

    `InternalEnrichmentConnector` (connectors-sdk) listens to enrichment messages, checks
    the scope and the TLP, then sends the original bundle enriched with the objects
    built by `SpurIPProcessor`.

    - traceback.print_exc(): This function prints the traceback of the exception to the standard error (stderr).
    The traceback includes information about the point in the program where the exception occurred,
    which is very useful for debugging purposes.
    - exit(1): effective way to terminate a Python program when an error is encountered.
    It signals to the operating system and any calling processes that the program did not complete successfully.
    """
    try:
        settings = ConnectorSettings()

        connector = InternalEnrichmentConnector(
            settings=settings,
            enrichment_processors=[SpurIPProcessor()],
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
