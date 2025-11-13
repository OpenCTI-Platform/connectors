# -*- coding: utf-8 -*-
"""OpenCTI Malpedia connector main module."""
import sys
import traceback

from malpedia_connector import MalpediaConnector

if __name__ == "__main__":
    try:
        connector = MalpediaConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
