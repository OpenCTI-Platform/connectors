"""Start the NIST NVD CVE enrichment connector."""

import sys
import traceback

from src.connector import CVEConnector

if __name__ == "__main__":
    try:
        connector = CVEConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
