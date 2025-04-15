"""OpenCTI CVE connector main module"""

import time

from connector import CVEConnector

if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        connector = CVEConnector()
        connector.run()
    except Exception as err:
        print(err)
        time.sleep(10)
        exit(0)
