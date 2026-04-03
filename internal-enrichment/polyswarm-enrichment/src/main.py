#!/usr/bin/env python3
"""PolySwarm Internal Enrichment Connector for OpenCTI.

Reads configuration from environment variables (or config.yml.sample),
initialises the OpenCTI helper, and starts the enrichment listener.
"""

import sys
import traceback

from pycti import OpenCTIConnectorHelper

from polyswarm_enrichment import ConnectorSettings, ConnectorTemplate


def main():
    """Entry point for the PolySwarm Internal Enrichment Connector."""
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(),
            playbook_compatible=True,
        )
        connector = ConnectorTemplate(settings=settings, helper=helper)
        connector.run()
    except KeyboardInterrupt:
        print("\nConnector stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error starting connector: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
