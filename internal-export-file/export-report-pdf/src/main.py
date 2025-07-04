import traceback

from export_report_pdf.connector import Connector


def main() -> None:
    try:
        connector = Connector()
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    main()
