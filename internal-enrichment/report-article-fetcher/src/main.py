import traceback

from connector import ConnectorSettings, ReportArticleFetcherConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(),
            playbook_compatible=True,  # every code path sends a bundle back to a playbook
        )
        connector = ReportArticleFetcherConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
