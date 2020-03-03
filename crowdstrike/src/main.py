# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike connector main module."""

from crowdstrike import CrowdStrike

if __name__ == "__main__":
    connector = CrowdStrike()
    connector.run()
