import traceback

from src.connector.mispConnector import ConnectorMISP

if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        connector = ConnectorMISP()
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
