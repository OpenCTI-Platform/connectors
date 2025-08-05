import sys
import time

from threatmatch.connector import Connector


def main() -> None:
    connector = Connector()
    connector.run()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
