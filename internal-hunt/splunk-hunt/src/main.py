"""Entry point of the Splunk hunt connector."""

import traceback

from splunk_hunt import ConnectorSettings, SplunkHuntConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = SplunkHuntConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
