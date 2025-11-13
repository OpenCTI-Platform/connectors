import sys
import time

from connector import CPEConnector


class CustomConnector(CPEConnector):
    def __init__(self):
        super().__init__()


if __name__ == "__main__":
    try:
        connector = CustomConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
