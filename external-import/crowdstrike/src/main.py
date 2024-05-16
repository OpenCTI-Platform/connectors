# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike connector main module."""
import time

from crowdstrike_feeds_connector import CrowdStrike

if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        connector = CrowdStrike()
        connector.run()
    except Exception as err:
        print(err)
        time.sleep(10)
        exit(0)
