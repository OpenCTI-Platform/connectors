"""Connector entry point."""

import traceback

from connector import ConnectorSettings, ConnectorState
from connector.data_processors import MirageFeedProcessor
from connectors_sdk import ExternalImportConnector as MirageConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        state = ConnectorState()
        connector = MirageConnector(
            settings=settings,
            state=state,
            data_processors=[MirageFeedProcessor()],
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
