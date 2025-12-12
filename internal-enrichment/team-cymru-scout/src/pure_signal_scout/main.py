import sys

from .connector import PureSignalScoutConnector

if __name__ == "__main__":
    try:
        print("Starting Pure Signal Scout Connector...")
        connector = PureSignalScoutConnector()
        connector.helper.connector_logger.info(
            "[PureSignalScout] Connector initialized successfully"
        )
        connector.start()
    except Exception as e:
        print(f"Failed to start connector: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
