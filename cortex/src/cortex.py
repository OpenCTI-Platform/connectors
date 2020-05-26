# -*- coding: utf-8 -*-
"""OpenCTI Cortex connector main module."""

from cortex import Cortex

if __name__ == "__main__":
    connector = Cortex()
    connector.run()
