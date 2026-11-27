"""Connector entry point: load the settings and state, then start the import loop.

`ExternalImportConnector.start()` (from `connectors-sdk`) runs the loop: every
`duration_period`, it calls the processor's `collect()` then `transform()`,
sends the bundles to OpenCTI and saves the state.
"""

import sys
import traceback

from connector import ConnectorSettings, ConnectorState
from connector.data_processors import FeedProcessor
from connectors_sdk import ExternalImportConnector

if __name__ == "__main__":
    try:
        connector = ExternalImportConnector(
            settings=ConnectorSettings(),
            state=ConnectorState(),
            data_processors=[FeedProcessor()],
        )
        connector.start()
    except Exception:
        # Full traceback and a non-zero exit code, so that Docker or the
        # orchestrator sees the failure.
        traceback.print_exc()
        sys.exit(1)
