import sys
import traceback

from connectors_sdk import ExternalImportConnector
from crowdstrike_incidents import (
    AlertProcessor,
    ConnectorSettings,
    CrowdstrikeIncidentsState,
)

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = ExternalImportConnector(
            settings=settings,
            data_processors=[AlertProcessor()],
            state=CrowdstrikeIncidentsState(),
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
