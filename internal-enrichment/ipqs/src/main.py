# -*- coding: utf-8 -*-
"""IPQS connector main file."""

from ipqs import IPQSConnector

if __name__ == "__main__":
    connector = IPQSConnector()
    connector.start()
