"""Main entry point for the connector."""

import logging
import os
import sys
import traceback

from connector.src.custom.exceptions import GTIConfigurationError
from connector.src.octi.connector import Connector
from dotenv import load_dotenv
from pycti import (  # type: ignore  # Missing library stubs
    OpenCTIConnectorHelper,
)

logger = logging.getLogger(__name__)


def _check_if_dev_env() -> None:
    try:
        dev_mode = os.getenv("CONNECTOR_DEV_MODE", "").lower() == "true"
        if dev_mode:
            for k in list(os.environ):
                if k.upper().startswith(("CONNECTOR_", "GTI_", "OPENCTI_")):
                    if k != "CONNECTOR_DEV_MODE":
                        del os.environ[k]
        else:
            load_dotenv(override=True)
    except Exception as env_err:
        logger.error(f"Error setting up environment: {str(env_err)}")
        sys.exit(1)


def main() -> None:
    """Define the main function to run the connector."""
    try:
        _check_if_dev_env()
        try:
            from connector.src.custom.configs.gti_config import GTIConfig
            from connector.src.octi.global_config import GlobalConfig

            global_config = GlobalConfig()
            try:
                global_config.add_config_class(GTIConfig)
            except GTIConfigurationError as config_err:
                logger.error(f"Failed to load GTI configuration: {str(config_err)}")
                sys.exit(1)
        except Exception as config_err:
            logger.error(f"Failed to load configuration: {str(config_err)}")
            traceback.print_exc()
            sys.exit(1)

        try:
            octi_helper = OpenCTIConnectorHelper(config=global_config.to_dict())
        except Exception as helper_err:
            logger.error(f"Failed to initialize OpenCTI helper: {str(helper_err)}")
            traceback.print_exc()
            sys.exit(1)

        try:
            connector = Connector(global_config, octi_helper)
            connector.run()
        except (KeyboardInterrupt, SystemExit):
            logger.info("Connector stopped by user/system")
            sys.exit(0)
        except Exception as run_err:
            logger.error(f"Connector execution failed: {str(run_err)}")
            traceback.print_exc()
            sys.exit(1)

    except Exception as unexpected_err:
        logger.error(f"Unexpected startup error: {str(unexpected_err)}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
