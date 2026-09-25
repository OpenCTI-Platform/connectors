"""Entrypoint of the Wiz Cloud external import connector."""

import sys
import traceback

from connectors_sdk import ExternalImportConnector
from wiz_cloud import ConnectorSettings, WizConnectorState
from wiz_cloud.processors import WizIssuesProcessor

if __name__ == "__main__":
    try:
        connector = ExternalImportConnector(
            settings=ConnectorSettings(),
            data_processors=[WizIssuesProcessor()],
            state=WizConnectorState(),
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
