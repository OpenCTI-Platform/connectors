"""Main entry point for the connector."""

import logging
import sys
import traceback

from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.exceptions import GTIConfigurationError
from connector.src.octi.connector import Connector
from connector.src.octi.global_config import GlobalConfig
from dotenv import load_dotenv
from pycti import (  # type: ignore  # Missing library stubs
    OpenCTIConnectorHelper,
)

logger = logging.getLogger(__name__)


def main() -> None:
    """Define the main function to run the connector."""
    try:
        global_config = load_conf()
        if global_config:
            octi_helper = load_helper(global_config)
            if octi_helper:
                connector_run(global_config, octi_helper)
    except Exception as unexpected_err:
        logger.error(f"Unexpected startup error: {str(unexpected_err)}")
        traceback.print_exc()
        sys.exit(1)


def load_conf() -> "GlobalConfig | None":
    """Load Global and GTI Configuration."""
    try:
        load_dotenv(override=True)
        global_config = GlobalConfig()
        _add_gticonf(global_config)
        return global_config
    except Exception as config_err:
        logger.error(f"Failed to load configuration: {str(config_err)}")
        raise


def _add_gticonf(global_config: "GlobalConfig") -> None:
    """Load GTI Configuration."""
    try:
        global_config.add_config_class(GTIConfig)
    except GTIConfigurationError as config_err:
        logger.error(f"Failed to load GTI configuration: {str(config_err)}")


def load_helper(global_config: "GlobalConfig") -> "OpenCTIConnectorHelper | None":
    """Load OCTIHelper."""
    try:
        octi_helper = OpenCTIConnectorHelper(config=global_config.to_dict())
        return octi_helper
    except Exception as helper_err:
        logger.error(f"Failed to initialize OpenCTI helper: {str(helper_err)}")
        raise


def connector_run(
    global_config: "GlobalConfig", octi_helper: "OpenCTIConnectorHelper"
) -> None:
    """Start the connector."""
    try:
        connector = Connector(global_config, octi_helper)
        connector.run()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Connector stopped by user/system")
    except Exception as run_err:
        logger.error(f"Connector execution failed: {str(run_err)}")


if __name__ == "__main__":
    main()
