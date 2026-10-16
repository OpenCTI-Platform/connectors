"""Connector entry point.

Steps performed below:
    1. Load and validate the connector's configuration (`ConnectorSettings`).
       Values come from environment variables or `config.yml`
       -- see `connector/settings.py` for the full list of available options.
    2. Instantiate the connector and start it. `connector.start()` is
       inherited from `InternalHuntConnector` (`connectors-sdk`): it checks
       that the installed pycti supports hunt connectors, registers the hunt
       platform in OpenCTI and listens to the hunt runs dispatched to the
       connector.

Notes:
    Any exception raised during startup is printed with a full traceback
    and the process exits with a non-zero status code so that Docker or
    any orchestration tool can detect the failure.
"""

import traceback

from connector import ConnectorSettings, TemplateConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        connector = TemplateConnector(settings=settings)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
