"""Entry point of the SentinelOne hunt connector."""

import traceback

from sentinelone_hunt import ConnectorSettings, SentinelOneHuntConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = SentinelOneHuntConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
