"""Entry point of the infrastructure tracker hunt connector."""

import traceback

from infrastructure_tracker import ConnectorSettings, InfrastructureTrackerConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = InfrastructureTrackerConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
