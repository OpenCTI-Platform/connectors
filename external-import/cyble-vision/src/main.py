"""Cyble Vision external-import connector entry point."""

import traceback

from connector import ConnectorSettings, ConnectorState
from connector.data_processors import (
    AdvisoriesProcessor,
    AlertsProcessor,
    NewsfeedProcessor,
    NewsflashProcessor,
)
from connectors_sdk import ExternalImportConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        state = ConnectorState()
        cfg = settings.cyble_vision

        processors = [AlertsProcessor()]
        if cfg.enable_advisories:
            processors.append(AdvisoriesProcessor())
        if cfg.enable_newsfeed:
            processors.append(NewsfeedProcessor())
        if cfg.enable_newsflash:
            processors.append(NewsflashProcessor())

        connector = ExternalImportConnector(
            settings=settings,
            state=state,
            data_processors=processors,
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
