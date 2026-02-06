import sys

from .connector import ScoutSearchConnectorConnector

if __name__ == "__main__":
    try:
        print("Starting Scout Search Connector Connector...")
        connector = ScoutSearchConnectorConnector()
        connector.helper.connector_logger.info(
            "[ScoutSearchConnector] Connector initialized successfully"
        )
        connector.start()
    except Exception as e:
        print(f"Failed to start connector: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
