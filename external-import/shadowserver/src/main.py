import traceback

from shadowserver.connector import CustomConnector

if __name__ == "__main__":
    try:
        connector = CustomConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
