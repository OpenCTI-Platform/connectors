"""
IPGeolocation.io OpenCTI Connector — Entrypoint
=================================================

Usage::

    python -m src.main

Or as a Docker container with the appropriate environment variables.
"""

import sys
import time
import traceback

from .connector import IPGeolocationConnector


def main() -> None:
    try:
        connector = IPGeolocationConnector()
        connector.start()
    except Exception as exc:
        print(
            f"[FATAL] IPGeolocation.io connector failed to start: {exc}",
            file=sys.stderr,
        )
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)


if __name__ == "__main__":
    main()
