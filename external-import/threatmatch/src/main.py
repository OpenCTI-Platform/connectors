import sys
import traceback

from threatmatch.connector import Connector


def main() -> None:
    connector = Connector()
    connector.run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
