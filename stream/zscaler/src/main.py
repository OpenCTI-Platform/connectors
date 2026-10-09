import sys
import time
import traceback

from pycti import OpenCTIConnectorHelper
from stream_connector import ZscalerConnector
from stream_connector.client import ZscalerClient
from stream_connector.settings import ConnectorSettings

LEGACY_CREDENTIAL_FIELDS = {"username", "password", "api_key"}

if __name__ == "__main__":
    try:
        # Load and validate configuration via Pydantic settings
        config = ConnectorSettings()

        # Initialize the helper
        helper = OpenCTIConnectorHelper(config=config.to_helper_config())

        legacy_fields = LEGACY_CREDENTIAL_FIELDS & config.zscaler.model_fields_set
        if legacy_fields:
            helper.connector_logger.warning(
                "Legacy Zscaler API credentials are ignored, the connector uses Zscaler OneAPI",
                {"fields": sorted(legacy_fields)},
            )

        client = ZscalerClient(
            logger=helper.connector_logger,
            client_id=config.zscaler.client_id,
            client_secret=config.zscaler.client_secret.get_secret_value(),
            vanity_domain=config.zscaler.vanity_domain,
            cloud=config.zscaler.cloud,
            ssl_verify=config.zscaler.ssl_verify,
        )
        # Fail fast on invalid OneAPI credentials
        client.authenticate()

        connector = ZscalerConnector(
            helper=helper,
            client=client,
            zscaler_blacklist_name=config.zscaler.blacklist_name,
        )
        connector.start()

    except Exception:
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)
