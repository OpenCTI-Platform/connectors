"""Connector entry point: import the custom IOA rules deployed in CrowdStrike Falcon."""

import traceback

from connector import ConnectorSettings, ConnectorState, CrowdStrikeRulesProcessor
from connectors_sdk import ExternalImportConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = ExternalImportConnector(
            settings=settings,
            state=ConnectorState(),
            data_processors=[CrowdStrikeRulesProcessor()],
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
