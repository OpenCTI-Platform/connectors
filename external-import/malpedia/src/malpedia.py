# -*- coding: utf-8 -*-
"""OpenCTI Malpedia connector main module."""

from malpedia import Malpedia

if __name__ == "__main__":
    connector = Malpedia()
    connector.run()
