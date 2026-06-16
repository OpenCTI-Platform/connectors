import sys
import traceback

from connectors_sdk import ExternalImportConnector
from shadowserver.dataprocessor import ShadowserverProcessor
from shadowserver.settings import ConnectorSettings

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = ExternalImportConnector(
            settings=settings,
            data_processors=[ShadowserverProcessor()],
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
