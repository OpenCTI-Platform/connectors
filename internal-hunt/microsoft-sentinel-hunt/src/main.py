"""Entry point of the Microsoft Sentinel hunt connector."""

import traceback

from microsoft_sentinel_hunt import ConnectorSettings, MicrosoftSentinelHuntConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = MicrosoftSentinelHuntConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
