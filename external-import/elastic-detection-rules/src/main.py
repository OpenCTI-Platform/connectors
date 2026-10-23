"""Connector entry point: import the detection rules deployed in Elastic Security."""

import traceback

from connector import ConnectorSettings, ConnectorState, ElasticRulesProcessor
from connectors_sdk import ExternalImportConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = ExternalImportConnector(
            settings=settings,
            state=ConnectorState(),
            data_processors=[ElasticRulesProcessor()],
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
