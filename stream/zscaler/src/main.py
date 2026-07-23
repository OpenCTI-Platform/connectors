import sys
import time
import traceback

from pycti import OpenCTIConnectorHelper
from stream_connector import ZscalerConnector
from stream_connector.settings import ConnectorSettings

CONFIG_FILE_PATH = "/opt/opencti-connector-zscaler/config.yml"

if __name__ == "__main__":
    try:
        # Load and validate configuration via Pydantic settings
        config = ConnectorSettings()

        # Initialize the helper
        helper = OpenCTIConnectorHelper(config=config.to_helper_config())

        # Initialize the connector with the validated settings
        connector = ZscalerConnector(
            config_path=CONFIG_FILE_PATH,
            helper=helper,
            opencti_url=str(config.opencti.url),
            opencti_token=config.opencti.token,
            ssl_verify=config.zscaler.ssl_verify,
            zscaler_username=config.zscaler.username,
            zscaler_password=config.zscaler.password.get_secret_value(),
            zscaler_api_key=config.zscaler.api_key.get_secret_value(),
            zscaler_blacklist_name=config.zscaler.blacklist_name,
        )

        connector.authenticate_with_zscaler()
        connector.start()

    except Exception:
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)
