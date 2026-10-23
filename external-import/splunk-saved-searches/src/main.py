"""Connector entry point: import the saved searches deployed in Splunk."""

import traceback

from connector import ConnectorSettings, ConnectorState, SplunkRulesProcessor
from connectors_sdk import ExternalImportConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = ExternalImportConnector(
            settings=settings,
            state=ConnectorState(),
            data_processors=[SplunkRulesProcessor()],
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
