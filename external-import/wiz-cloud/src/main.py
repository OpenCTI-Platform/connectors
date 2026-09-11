"""Entrypoint of the Wiz Cloud external import connector."""

import sys
import traceback

from connectors_sdk import ExternalImportConnector
from wiz_cloud import ConnectorSettings, WizConnectorState
from wiz_cloud.processors import WizIssuesProcessor

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = ExternalImportConnector(
            settings=settings,
            # A single processor: vulnerabilities are fetched while each issue
            # is converted, so they share its bundle and its work.
            data_processors=[WizIssuesProcessor()],
            state=WizConnectorState(),
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
