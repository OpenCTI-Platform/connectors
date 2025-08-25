"""OpenCTI CVE connector main module"""

import traceback

from src.connector import CVEConnector

if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        connector = CVEConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
