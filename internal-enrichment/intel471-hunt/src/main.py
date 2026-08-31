"""Entry point for the Intel 471 Hunter internal enrichment connector."""

import traceback

from pycti import OpenCTIConnectorHelper
from src.connector import HunterEnrichmentConnector
from src.settings import ConnectorSettings


def main() -> None:
    settings = ConnectorSettings()

    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(),
        playbook_compatible=True,
    )

    connector = HunterEnrichmentConnector(config=settings, helper=helper)
    connector.run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        exit(1)
