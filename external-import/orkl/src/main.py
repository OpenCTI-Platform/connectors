from __future__ import annotations

import sys
import traceback

from connectors_sdk import ExternalImportConnector
from orkl import ConnectorSettings, OrklReportProcessor

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = ExternalImportConnector(
            settings=settings,
            data_processors=[OrklReportProcessor()],
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
