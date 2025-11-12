import sys
import time

from importer import StreamImporterConnector

if __name__ == "__main__":
    try:
        connector = StreamImporterConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
