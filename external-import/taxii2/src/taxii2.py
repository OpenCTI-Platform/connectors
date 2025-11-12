import traceback

from connector import Connector

if __name__ == "__main__":
    try:
        connector = Connector()
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
