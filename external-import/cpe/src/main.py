import sys
import time

from connector import CPEConnector

if __name__ == "__main__":
    try:
        connector = CPEConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
