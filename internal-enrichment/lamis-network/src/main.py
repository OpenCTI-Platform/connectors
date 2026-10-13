# -*- coding: utf-8 -*-
"""Lamis Network connector main entrypoint."""

import traceback

from lamis_network import ConnectorSettings, LamisNetworkConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(),
            playbook_compatible=True,
        )
        connector = LamisNetworkConnector(config=settings, helper=helper)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
