# -*- coding: utf-8 -*-
"""OpenCTI Valhalla connector main module."""

from valhalla import Valhalla

if __name__ == "__main__":
    connector = Valhalla()
    connector.run()
