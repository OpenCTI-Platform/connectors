"""Connector entry point: one processor per configured HoneyLabs collection."""

import traceback

from connectors_sdk import ExternalImportConnector as HoneyLabsConnector

from connector import ConnectorSettings, ConnectorState
from connector.data_processors import IndicatorsProcessor

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        state = ConnectorState()
        processors = [
            IndicatorsProcessor(collection)
            for collection in settings.honeylabs.collections
        ]
        connector = HoneyLabsConnector(
            settings=settings, state=state, data_processors=processors
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
