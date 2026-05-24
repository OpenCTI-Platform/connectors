# -*- coding: utf-8 -*-
"""OpenCTI ReportImporter connector main module."""

import traceback

from deprecation import deprecated

from import_doc_ai import ConfigConnector, Connector
from pycti import OpenCTIConnectorHelper, __version__


@deprecated(
    deprecated_in="7.260522.0",
    removed_in="8.0.0",
    current_version=__version__,
    details="Configure the xtm_one_intent in env / configuration file instead."
)
def xtm_one_special_registration():
    # If xtm one is supported, register intent for the connector
    # This code allows backward compatibility with previous versions of opencti not implementing xtm one
    # Will be removed after deprecation of legacy IA management
    if (
            hasattr(helper.connector, "xtm_one_intent")
            and helper.connector.xtm_one_intent is None
    ):
        # Register again the connector with the default intent
        try:
            helper.connector_logger.info("Registering XTM One intent")
            helper.connector.xtm_one_intent = "cti.stix_harvester"
            helper.api.connector.register(helper.connector)
        except Exception as e:
            helper.connector_logger.warning(
                "Failed to register XTM One intent, upgrade your OpenCTI", {"error": str(e)}
            )


if __name__ == "__main__":
    try:
        config = ConfigConnector()
        helper = OpenCTIConnectorHelper(config=config.load)
        xtm_one_special_registration()
        # Start the connector
        connector = Connector(config=config, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
