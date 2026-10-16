"""Entry point of the Silent Push hunt connector."""

import traceback

from silentpush_hunt import ConnectorSettings, SilentPushHuntConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = SilentPushHuntConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
