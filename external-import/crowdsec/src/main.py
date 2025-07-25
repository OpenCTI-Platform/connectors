# -*- coding: utf-8 -*-
"""CrowdSec external import connector main file."""

from time import sleep

from crowdsec import CrowdSecImporter

if __name__ == "__main__":
    try:
        crowdsec_connector = CrowdSecImporter()
        crowdsec_connector.run()
    except Exception as e:
        print(e)
        sleep(10)
        exit(0)
