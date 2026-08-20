#!/usr/bin/env python3
"""PolySwarm Internal Enrichment Connector for OpenCTI.

Reads configuration from environment variables (or config.yml.sample),
initialises the OpenCTI helper, and starts the enrichment listener.
"""

import sys
import traceback

from polyswarm_enrichment import ConnectorSettings, ConnectorTemplate
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(),
            playbook_compatible=True,
        )
        connector = ConnectorTemplate(settings=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
