# -*- coding: utf-8 -*-
"""OpenCTI Cluster25 connector main module."""

from cluster25 import Cluster25

if __name__ == "__main__":
    connector = Cluster25()
    connector.run()
