"""ReversingLabs Spectra Intelligence Submission connector entry point."""

import traceback

from connector import ConnectorSettings, ReversingLabsSpectraIntelConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(), playbook_compatible=True
        )

        connector = ReversingLabsSpectraIntelConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
