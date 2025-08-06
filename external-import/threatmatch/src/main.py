import sys
import traceback

from pycti import OpenCTIConnectorHelper
from threatmatch.config import ConnectorSettings
from threatmatch.connector import Connector


def main() -> None:
    config = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config.model_dump_pycti())

    connector = Connector(helper=helper, config=config)
    connector.run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
