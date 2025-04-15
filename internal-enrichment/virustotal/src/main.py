# -*- coding: utf-8 -*-
"""VirusTotal connector main file."""

import sys
import time

from virustotal import VirusTotalConnector

if __name__ == "__main__":
    try:
        connector = VirusTotalConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
