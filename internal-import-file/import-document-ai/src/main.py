# -*- coding: utf-8 -*-
"""OpenCTI ReportImporter connector main module."""

import traceback

from reportimporter import ReportImporter

if __name__ == "__main__":
    try:
        connector = ReportImporter()
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
