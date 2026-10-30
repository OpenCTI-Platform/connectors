"""Connector entry point: import the analytics rules deployed in Microsoft Sentinel."""

import traceback

from connector import ConnectorSettings, ConnectorState, SentinelRulesProcessor
from connectors_sdk import ExternalImportConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = ExternalImportConnector(
            settings=settings,
            state=ConnectorState(),
            data_processors=[SentinelRulesProcessor()],
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
