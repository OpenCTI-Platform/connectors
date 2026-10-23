import sys
import time
import traceback

from pycti import OpenCTIConnectorHelper
from stream_connector import ZscalerConnector
from stream_connector.client import (
    DEFAULT_LEGACY_API_BASE_URL,
    LegacyAuth,
    OneApiAuth,
    ZscalerClient,
)
from stream_connector.settings import ConnectorSettings

LEGACY_FIELDS = {"username", "password", "api_key", "api_base_url"}


def build_auth(
    config: ConnectorSettings, helper: OpenCTIConnectorHelper
) -> OneApiAuth | LegacyAuth:
    zscaler = config.zscaler
    legacy_fields = sorted(LEGACY_FIELDS & zscaler.model_fields_set)

    if zscaler.use_legacy_api:
        helper.connector_logger.warning(
            "The legacy Zscaler API authentication is deprecated and stops working "
            "when Zscaler removes it. Migrate to Zscaler OneAPI (see the connector README).",
            {"fields": legacy_fields},
        )
        values = zscaler.__dict__  # avoid pydantic's deprecated-field access warnings
        return LegacyAuth(
            api_base_url=str(values["api_base_url"] or DEFAULT_LEGACY_API_BASE_URL),
            username=values["username"],
            password=values["password"].get_secret_value(),
            api_key=values["api_key"].get_secret_value(),
        )

    if legacy_fields:
        helper.connector_logger.warning(
            "Legacy Zscaler API settings are ignored, the connector uses Zscaler OneAPI",
            {"fields": legacy_fields},
        )
    return OneApiAuth(
        client_id=zscaler.client_id,
        client_secret=zscaler.client_secret.get_secret_value(),
        vanity_domain=zscaler.vanity_domain,
        cloud=zscaler.cloud,
    )


if __name__ == "__main__":
    try:
        # Load and validate configuration via Pydantic settings
        config = ConnectorSettings()

        # Initialize the helper
        helper = OpenCTIConnectorHelper(config=config.to_helper_config())

        client = ZscalerClient(
            logger=helper.connector_logger,
            auth=build_auth(config, helper),
            ssl_verify=config.zscaler.ssl_verify,
        )
        # Fail fast on invalid credentials
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
