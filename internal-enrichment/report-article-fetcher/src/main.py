import traceback

from connector import ConnectorSettings
from connector.connector import run_workers
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        run_workers(
            settings,
            lambda: OpenCTIConnectorHelper(
                config=settings.to_helper_config(),
                playbook_compatible=True,  # every code path sends a bundle back to a playbook
            ),
        )
    except Exception:
        traceback.print_exc()
        exit(1)
