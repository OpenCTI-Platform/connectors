# -*- coding: utf-8 -*-
import sys
import time
import traceback

from pycti import OpenCTIConnectorHelper

from .xposedornot import ConnectorSettings, XposedOrNotConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(),
            playbook_compatible=True,
        )
        XposedOrNotConnector(config=settings, helper=helper).run()
    except Exception:
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)
