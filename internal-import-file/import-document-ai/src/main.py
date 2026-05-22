# -*- coding: utf-8 -*-
"""OpenCTI ReportImporter connector main module."""

import traceback

from import_doc_ai import ConfigConnector, Connector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        config = ConfigConnector()
        helper = OpenCTIConnectorHelper(config=config.load)
        # If xtm one enabled, register intent for the connector
        # This code allows backward compatibility with previous versions of opencti not implementing xtm one
        # Will be removed after deprecation of legacy IA management
        if (
            hasattr(helper.connector, "xtm_one_intent")
            and helper.connector.xtm_one_intent is None
        ):
            platform_about = helper.api.about()
            dependencies = platform_about.get("dependencies", [])
            xtm_one_available = any(
                dep.get("name") == "XTM-One" for dep in dependencies
            )
            if xtm_one_available:
                # Register again the connector with the default intent
                try:
                    helper.connector.xtm_one_intent = "cti.stix_harvester"
                    helper.api.connector.register(helper.connector)
                except Exception as e:
                    helper.connector_logger.error(
                        "Failed to register XTM One intent", {"error": str(e)}
                    )
        # Start the connector
        connector = Connector(config=config, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
