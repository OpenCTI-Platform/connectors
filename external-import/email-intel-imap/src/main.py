import sys
import traceback

from email_intel_imap.client import (
    BaseConnectorClient,
    ConnectorClient,
    GoogleOAuthClient,
)
from email_intel_imap.config import ConnectorSettings
from email_intel_imap.connector import Connector
from email_intel_imap.converter import ConnectorConverter
from pycti import OpenCTIConnectorHelper


def client_factory(config: ConnectorSettings) -> BaseConnectorClient:
    """
    Factory function to create a connector client based on the provided configuration.

    Args:
        config (ConnectorSettings): The configuration settings for the connector.

    Returns:
        ConnectorClient: An instance of the appropriate connector client.
    """
    if config.email_intel_imap.google_token_json is not None:
        return GoogleOAuthClient(
            host=config.email_intel_imap.host,
            port=config.email_intel_imap.port,
            username=config.email_intel_imap.username,
            token_json=config.email_intel_imap.google_token_json,
            mailbox=config.email_intel_imap.mailbox,
        )

    # elif TODO: Add other authentication methods here
    #     return OtherAuthClient(...)

    return ConnectorClient(
        host=config.email_intel_imap.host,
        port=config.email_intel_imap.port,
        username=config.email_intel_imap.username,
        password=config.email_intel_imap.password,
        mailbox=config.email_intel_imap.mailbox,
    )


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
        author_name="Email Intel IMAP",
        author_description="Email Intel IMAP Connector",
        tlp_level=config.email_intel_imap.tlp_level,
        attachments_mime_types=config.email_intel_imap.attachments_mime_types,
    )

    client = client_factory(config=config)

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
