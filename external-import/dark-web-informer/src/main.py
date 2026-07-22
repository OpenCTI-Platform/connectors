import traceback

from connector import ConnectorSettings, DarkWebInformerConnector
from pycti import OpenCTIConnectorHelper


def main() -> None:
    """Entry point of the connector."""
    settings = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    connector = DarkWebInformerConnector(helper=helper, settings=settings)
    connector.run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        exit(1)
