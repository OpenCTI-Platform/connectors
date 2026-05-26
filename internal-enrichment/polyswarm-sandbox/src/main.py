"""Entry point for the PolySwarm Sandbox connector.

Reads configuration from environment variables (or config.yml.sample),
initialises the OpenCTI helper, and starts the enrichment listener.
Runs as a long-lived process inside Docker or locally during development.
"""

import traceback

from connector import ConnectorSettings, PolySwarmSandboxConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        # ConnectorSettings reads OPENCTI_*, CONNECTOR_*, and POLYSWARM_* env vars
        settings = ConnectorSettings()
        # playbook_compatible=True ensures bundles are returned even on error,
        # so downstream playbook nodes always receive input.
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(),
            playbook_compatible=True,
        )
        connector = PolySwarmSandboxConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
