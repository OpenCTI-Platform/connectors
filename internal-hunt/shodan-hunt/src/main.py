"""Entry point of the Shodan hunt connector."""

import traceback

from shodan_hunt import ConnectorSettings, ShodanHuntConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = ShodanHuntConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
