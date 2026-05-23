"""Entry point for the OpenCTI Datasets connector.

On uncaught exception we print the traceback to stderr (so the failing call
is actionable in the connector log) and exit with status 1 so the
orchestrator (Docker / systemd / Kubernetes) can detect the failure and
restart the container.

``sys.exit`` is preferred over the builtin ``exit``: the latter is injected
by the ``site`` module and is intended mainly for interactive use, while
``sys.exit`` is guaranteed to be present in any runtime environment.
"""

import sys
import traceback

from connector import ConnectorSettings, OpenCTI
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = OpenCTI(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
