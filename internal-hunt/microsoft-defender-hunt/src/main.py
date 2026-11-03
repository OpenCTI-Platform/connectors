"""Entry point of the Microsoft Defender XDR hunt connector."""

import traceback

from microsoft_defender_hunt import ConnectorSettings, MicrosoftDefenderHuntConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = MicrosoftDefenderHuntConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
