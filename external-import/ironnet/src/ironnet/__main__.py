"""IronNet connector"""

import traceback

from ironnet.connector import IronNetConnector

if __name__ == "__main__":
    try:
        IronNetConnector().start()
    except Exception:
        traceback.print_exc()
        exit(1)
