import sys
import traceback

from connectors_sdk import ExternalImportConnector
from zerofox_alerts import ConnectorSettings, ZerofoxAlertsProcessor

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = ExternalImportConnector(
            settings=settings,
            data_processors=[ZerofoxAlertsProcessor()],
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
