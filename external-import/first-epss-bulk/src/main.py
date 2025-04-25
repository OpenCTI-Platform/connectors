import sys
import traceback

from connector import FirstEPSSConnector

if __name__ == "__main__":
    try:
        connector = FirstEPSSConnector()
        connector.run()
    except Exception as e:
        print(e)
        traceback.print_exc()
        sys.exit(1)
