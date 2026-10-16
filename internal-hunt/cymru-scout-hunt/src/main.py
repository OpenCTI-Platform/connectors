"""Entry point of the Team Cymru Scout hunt connector."""

import traceback

from cymru_scout_hunt import ConnectorSettings, CymruScoutHuntConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = CymruScoutHuntConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
