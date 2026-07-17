import traceback

from pycti import OpenCTIConnectorHelper

from connector import ConnectorSettings, EmailCasesConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(),
        )
        connector = EmailCasesConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
