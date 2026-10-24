"""Main entry point for the Censys Enrichment connector."""

import sys
import traceback


def main() -> None:
    try:
        from censys_enrichment.client import Client
        from censys_enrichment.connector import Connector
        from censys_enrichment.settings import ConfigLoader
        from pycti import OpenCTIConnectorHelper

        config = ConfigLoader()
        helper = OpenCTIConnectorHelper(
            config=config.to_helper_config(),
            playbook_compatible=True,
        )
        client = Client(
            organisation_id=config.censys_enrichment.organisation_id.get_secret_value(),
            token=config.censys_enrichment.token.get_secret_value(),
        )
        connector = Connector(
            config=config,
            helper=helper,
            client=client,
        )
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
