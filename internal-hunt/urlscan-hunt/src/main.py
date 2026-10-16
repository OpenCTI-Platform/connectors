"""Entry point of the urlscan.io hunt connector."""

import traceback

from urlscan_hunt import ConnectorSettings, UrlscanHuntConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = UrlscanHuntConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
