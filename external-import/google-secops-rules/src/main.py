"""Connector entry point: import the detection rules deployed in Google SecOps."""

import traceback

from connector import ConnectorSettings, ConnectorState, GoogleSecOpsRulesProcessor
from connectors_sdk import ExternalImportConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = ExternalImportConnector(
            settings=settings,
            state=ConnectorState(),
            data_processors=[GoogleSecOpsRulesProcessor()],
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
