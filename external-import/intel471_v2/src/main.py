import sys
import traceback

from intel471 import ConnectorSettings, Intel471Connector
from pycti import OpenCTIConnectorHelper, OpenCTINGConnectorHelper

if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        settings = ConnectorSettings()

        # Detached opencti-ng mode: when `opencti_ng_url` + `opencti_ng_jwt` are
        # configured (config.yml or OPENCTI_NG_* env), ingest directly into
        # opencti-ng over a JWT (no OpenCTI worker/queue). The write tenant and
        # connector id are read from the JWT; run state lives server-side.
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
                    },
                }
            )
        else:
            helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = Intel471Connector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
