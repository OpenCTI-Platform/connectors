"""Connector entry point.

Wires together the configuration, state and data processors, then starts the
external-import loop provided by ``connectors-sdk``'s ``ExternalImportConnector``.
On each run the connector reads the Darkmoon OSS findings store from disk,
converts new campaigns to STIX and sends them to OpenCTI, then waits
``duration_period`` before running again.
"""

import traceback

from connector import ConnectorSettings, ConnectorState
from connector.data_processors import FindingsProcessor
from connectors_sdk import ExternalImportConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        state = ConnectorState()

        data_processors = []
        if settings.darkmoon.import_findings:
            data_processors.append(FindingsProcessor())

        connector = ExternalImportConnector(
            settings=settings,
            state=state,
            data_processors=data_processors,
        )
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
