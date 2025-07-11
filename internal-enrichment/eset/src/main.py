import traceback

from eset import EsetConnector

if __name__ == "__main__":
    try:
        connector = EsetConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
