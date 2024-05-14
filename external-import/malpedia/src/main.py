# -*- coding: utf-8 -*-
"""OpenCTI Malpedia connector main module."""
import time

from malpedia_connector import MalpediaConnector

if __name__ == "__main__":
    try:
        connector = MalpediaConnector()
        connector.start()
    except Exception as err:
        print(err)
        time.sleep(10)
        exit(0)
