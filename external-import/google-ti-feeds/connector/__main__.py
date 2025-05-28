"""Main entry point for the connector."""

import os
import traceback

from connector.src.octi.connector import Connector
from dotenv import load_dotenv
from pycti import OpenCTIConnectorHelper  # type: ignore


def main() -> None:
    """Define the main function to run the connector."""
    # noinspection PyBroadException
    try:
        dev_mode = os.getenv("CONNECTOR_DEV_MODE", "").lower() == "true"
        if dev_mode:
            for k in list(os.environ):
                if k.upper().startswith(("CONNECTOR_", "GTI_", "OPENCTI_")):
                    if k != "CONNECTOR_DEV_MODE":
                        del os.environ[k]
        else:
            load_dotenv(override=True)

        from connector.src.custom.configs.gti_config import GTIConfig
        from connector.src.octi.global_config import GlobalConfig

        global_config = GlobalConfig()
        global_config.add_config_class(GTIConfig)

        octi_helper = OpenCTIConnectorHelper(config=global_config.to_dict())

        connector = Connector(global_config, octi_helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    main()
