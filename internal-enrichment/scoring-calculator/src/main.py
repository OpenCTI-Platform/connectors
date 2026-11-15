import traceback

from internal_enrichment_connector import ConnectorScoring
from internal_enrichment_connector.settings import ConnectorSettings
from pycti import OpenCTIApiClient, OpenCTIConnectorHelper

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
        # playbook_compatible=True only if a bundle is sent !
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(), playbook_compatible=True
        )
        api = OpenCTIApiClient(
            url=str(settings.opencti.url),
            token=settings.opencti.token.get_secret_value(),
        )

        connector = ConnectorScoring(settings=settings, helper=helper, api=api)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
