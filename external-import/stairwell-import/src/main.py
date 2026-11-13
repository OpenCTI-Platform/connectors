import traceback

from connector import ConnectorSettings, ConnectorState
from connector.data_processors import MalEvalFilesProcessor
from connectors_sdk import ExternalImportConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = ExternalImportConnector(
            settings=settings,
            state=ConnectorState(),
            data_processors=[MalEvalFilesProcessor()],
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
