# -*- coding: utf-8 -*-
"""OpenCTI ReportImporter connector main module."""

import traceback

from pycti import OpenCTIConnectorHelper
from import_doc_ai import ConfigConnector, Connector

if __name__ == "__main__":
    try:
        config = ConfigConnector()
        helper = OpenCTIConnectorHelper(config=config.load)

        connector = Connector(config=config, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
