# -*- coding: utf-8 -*-
"""Entry point for the XposedOrNot internal-enrichment connector."""

import traceback

from pycti import OpenCTIConnectorHelper
from src.xposedornot import ConnectorSettings, XposedOrNotConnector


def main() -> None:
    settings = ConnectorSettings()
    helper = OpenCTIConnectorHelper(
        config=settings.to_helper_config(),
        playbook_compatible=True,
    )
    XposedOrNotConnector(config=settings, helper=helper).run()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        exit(1)
