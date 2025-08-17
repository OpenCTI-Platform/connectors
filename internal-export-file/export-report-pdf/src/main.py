import traceback

from export_report_pdf.config import ConnectorConfig
from export_report_pdf.connector import Connector
from pycti import OpenCTIConnectorHelper


def main() -> None:
    try:
        config = ConnectorConfig()
        helper = OpenCTIConnectorHelper(config=config.load)

        connector = Connector(config=config, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    main()
