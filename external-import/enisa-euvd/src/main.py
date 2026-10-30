"""Connector entry point.

Loads the connector's settings and persisted state, builds the single
`VulnerabilityProcessor`, and starts the `ExternalImportConnector` (from
`connectors-sdk`), which runs the collect -> transform -> send loop, persists
state, and waits `duration_period` between runs.
"""

import traceback

from connectors_sdk import ExternalImportConnector
from enisa_euvd import ConnectorSettings, ConnectorState
from enisa_euvd.processors.vulnerability_processor import VulnerabilityProcessor

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        state = ConnectorState()

        connector = ExternalImportConnector(
            settings=settings,
            state=state,
            data_processors=[VulnerabilityProcessor()],
        )
        connector.start()
    except Exception:
        # Full traceback to stderr + non-zero exit code so failures are
        # visible in logs and detected by whatever process manages the
        # connector's lifecycle (Docker, systemd, k8s, etc.).
        traceback.print_exc()
        exit(1)
