"""Main entry point for the connector."""

import logging
import sys
import traceback

from connector.src.custom.configs.gti_config import GTIConfig
from connector.src.custom.exceptions import GTIConfigurationError
from connector.src.octi.connector import Connector
from connector.src.octi.global_config import GlobalConfig
from dotenv import load_dotenv
from pycti import OpenCTIConnectorHelper, OpenCTINGConnectorHelper

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
        logger.error("Unexpected startup error", {"error": str(unexpected_err)})
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
        logger.error("Failed to load configuration", {"error": str(config_err)})
        raise


def _add_gticonf(global_config: "GlobalConfig") -> None:
    """Load GTI Configuration."""
    try:
        global_config.add_config_class(GTIConfig)
    except GTIConfigurationError as config_err:
        logger.error("Failed to load GTI configuration", {"error": str(config_err)})


def load_helper(global_config: "GlobalConfig"):
    """Load the OpenCTI helper.

    In detached opencti-ng mode (`opencti_ng.url` + `opencti_ng.jwt` configured)
    return an `OpenCTINGConnectorHelper` that ingests directly into opencti-ng
    over a JWT; otherwise the classic `OpenCTIConnectorHelper`.
    """
    try:
        ng = global_config.octi_ng_config
        if ng.enabled:
            cc = global_config.connector_config
            scope = cc.scope
            if isinstance(scope, str):
                scope = [s.strip() for s in scope.split(",") if s.strip()]
            return OpenCTINGConnectorHelper(
                config={
                    "opencti-ng": {"url": str(ng.url), "jwt": ng.jwt},
                    "connector": {
                        "name": cc.name,
                        "type": "EXTERNAL_IMPORT",
                        "scope": scope,
                        "duration_period": cc.duration_period,
                    },
                }
            )
        return OpenCTIConnectorHelper(config=global_config.to_dict())
    except Exception as helper_err:
        logger.error("Failed to initialize OpenCTI helper", {"error": str(helper_err)})
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
        logger.error("Connector execution failed", {"error": str(run_err)})


if __name__ == "__main__":
    main()
