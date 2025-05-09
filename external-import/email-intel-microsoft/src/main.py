import sys
import traceback

from email_intel_microsoft.client import ConnectorClient
from email_intel_microsoft.config import ConnectorSettings
from email_intel_microsoft.connector import Connector
from email_intel_microsoft.converter import ConnectorConverter
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
    converter = ConnectorConverter(
        helper=helper,
        author_name="Email Intel Microsoft",
        author_description="Email Intel Microsoft Connector",
        tlp_level=config.email_intel_microsoft.tlp_level,
    )
    client = ConnectorClient(
        tenant_id=config.email_intel_microsoft.tenant_id,
        client_id=config.email_intel_microsoft.client_id,
        client_secret=config.email_intel_microsoft.client_secret,
        email=config.email_intel_microsoft.email,
        mailbox=config.email_intel_microsoft.mailbox,
        attachments_mime_types=config.email_intel_microsoft.attachments_mime_types,
    )

    connector = Connector(
        config=config, helper=helper, converter=converter, client=client
    )

    connector.run(duration_period=config.connector.duration_period)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
