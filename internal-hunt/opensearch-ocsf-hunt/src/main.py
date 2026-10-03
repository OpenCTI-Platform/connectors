"""Entry point of the OpenSearch OCSF hunt connector."""

import traceback

from opensearch_ocsf_hunt import ConnectorSettings, OpenSearchOcsfHuntConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = OpenSearchOcsfHuntConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
