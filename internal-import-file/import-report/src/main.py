# -*- coding: utf-8 -*-
"""OpenCTI ReportImporter connector main module."""

from reportimporter import ReportImporter

if __name__ == "__main__":
    connector = ReportImporter()
    connector.start()
