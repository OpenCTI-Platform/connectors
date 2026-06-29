import traceback

from external_import_connector import ConnectorSettings, ConnectorURLhaus
from pycti import OpenCTIConnectorHelper, OpenCTINGConnectorHelper

if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        settings = ConnectorSettings()

        if settings.opencti_ng_enabled:
            helper = OpenCTINGConnectorHelper(
                config={
                    "opencti-ng": {
                        "url": str(settings.opencti_ng_url),
                        "jwt": settings.opencti_ng_jwt.get_secret_value(),
                    },
                    "connector": {
                        "name": settings.connector.name,
                        "type": "EXTERNAL_IMPORT",
                        "scope": settings.connector.scope,
                        "duration_period": settings.connector.duration_period,
                    },
                }
            )
        else:
            helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = ConnectorURLhaus(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
