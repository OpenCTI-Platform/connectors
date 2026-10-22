"""Entry point of the CrowdStrike LogScale hunt connector."""

import traceback

from crowdstrike_logscale_hunt import (
    ConnectorSettings,
    CrowdstrikeLogscaleHuntConnector,
)

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = CrowdstrikeLogscaleHuntConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
