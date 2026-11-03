"""Entry point of the Google SecOps hunt connector."""

import traceback

from google_secops_hunt import ConnectorSettings, GoogleSecopsHuntConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = GoogleSecopsHuntConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
