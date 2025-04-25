import sys
import traceback

from email_intel_imap.client import ConnectorClient
from email_intel_imap.config import ConnectorConfig
from email_intel_imap.connector import Connector
from email_intel_imap.converter import ConnectorConverter
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
    config = ConnectorConfig()
    helper = OpenCTIConnectorHelper(
        config=config.model_dump(mode="json", context={"mode": "pycti"})
    )
    converter = ConnectorConverter(
        helper=helper,
        author_name="Email Intel IMAP",
        author_description="Email Intel IMAP Connector",
        tlp_level=config.email_intel_imap.tlp_level,
        attachments_mime_types=config.email_intel_imap.attachments_mime_types,
    )
    client = ConnectorClient(
        host=config.email_intel_imap.host,
        port=config.email_intel_imap.port,
        username=config.email_intel_imap.username,
        password=config.email_intel_imap.password,
        mailbox=config.email_intel_imap.mailbox,
    )

    connector = Connector(
        config=config, helper=helper, converter=converter, client=client
    )

    connector.run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
