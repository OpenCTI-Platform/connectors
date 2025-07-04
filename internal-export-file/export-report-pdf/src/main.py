import sys
import time

from export_report_pdf.connector import Connector


def main() -> None:
    try:
        connector = Connector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)


if __name__ == "__main__":
    main()
