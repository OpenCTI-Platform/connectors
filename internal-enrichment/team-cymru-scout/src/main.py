import sys

from pure_signal_scout import connector

if __name__ == "__main__":
    try:
        print("Starting Pure Signal Scout Connector...")
        connector = connector.PureSignalScoutConnector()
        connector.helper.connector_logger.info(
            "[PureSignalScout] Connector initialized successfully"
        )
        connector.start()
    except Exception as e:
        print(f"Failed to start connector: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
