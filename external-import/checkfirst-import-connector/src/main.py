from connector.connector import CheckfirstImportConnector
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


def main() -> None:
    settings = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    connector = CheckfirstImportConnector(config=settings, helper=helper)
    connector.run()


if __name__ == "__main__":
    main()
