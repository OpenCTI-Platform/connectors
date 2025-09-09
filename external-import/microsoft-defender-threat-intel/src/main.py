import sys
import traceback

from microsoft_defender_threat_intel.client import ConnectorClient
from microsoft_defender_threat_intel.config import ConnectorSettings
from microsoft_defender_threat_intel.connector import Connector
from microsoft_defender_threat_intel.converter import ConnectorConverter
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
        author_name="Microsoft Defender Threat Intel",
        author_description="Microsoft Defender Threat Intel Connector",
        tlp_level=config.microsoft_defender_threat_intel.tlp_level,
    )
    client = ConnectorClient(
        tenant_id=config.microsoft_defender_threat_intel.tenant_id,
        client_id=config.microsoft_defender_threat_intel.client_id,
        client_secret=config.microsoft_defender_threat_intel.client_secret,
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
