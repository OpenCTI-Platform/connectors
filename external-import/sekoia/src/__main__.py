import traceback

from pycti import OpenCTIConnectorHelper, OpenCTINGConnectorHelper
from src.connector import ConfigLoader, SekoiaConnector

if __name__ == "__main__":
    """
    Entry point of the script
    """
    try:
        config = ConfigLoader()

        # Detached opencti-ng mode: when `opencti_ng_url` + `opencti_ng_jwt` are
        # configured (config.yml or OPENCTI_NG_* env), ingest directly into
        # opencti-ng over a JWT (no OpenCTI worker/queue). The write tenant and
        # connector id are read from the JWT; run state lives server-side.
        if config.opencti_ng_enabled:
            helper = OpenCTINGConnectorHelper(
                config={
                    "opencti-ng": {
                        "url": str(config.opencti_ng_url),
                        "jwt": config.opencti_ng_jwt.get_secret_value(),
                    },
                    "connector": {
                        "name": config.connector.name,
                        "type": "EXTERNAL_IMPORT",
                        "scope": config.connector.scope,
                        "duration_period": config.connector.duration_period,
                    },
                }
            )
        else:
            helper = OpenCTIConnectorHelper(config=config.model_dump_pycti())

        connector = SekoiaConnector(config, helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
