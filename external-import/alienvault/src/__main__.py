import traceback

from alienvault import AlienVault, ConnectorSettings
from pycti import OpenCTIConnectorHelper, OpenCTINGConnectorHelper

if __name__ == "__main__":
    """
    Entry point of the script

    - traceback.print_exc(): This function prints the traceback of the exception to the standard error (stderr).
    The traceback includes information about the point in the program where the exception occurred,
    which is very useful for debugging purposes.
    - exit(1): effective way to terminate a Python program when an error is encountered.
    It signals to the operating system and any calling processes that the program did not complete successfully.
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
                        "duration_period": settings.connector.duration_period,
                    },
                }
            )
        else:
            helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = AlienVault(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
