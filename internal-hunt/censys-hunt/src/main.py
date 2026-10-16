"""Entry point of the Censys Platform hunt connector."""

import traceback

from censys_hunt import CensysHuntConnector, ConnectorSettings

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = CensysHuntConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
