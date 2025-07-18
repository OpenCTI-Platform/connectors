import os
import sys
import time
import traceback

import yaml
from pycti import OpenCTIConnectorHelper
from stream_connector import ZscalerConnector
from stream_connector.config_variables import load_config_variables

CONFIG_FILE_PATH = "/opt/opencti-connector-zscaler/config.yml"

if __name__ == "__main__":
    try:
        # Load config.yml
        config = {}
        if os.path.isfile(CONFIG_FILE_PATH):
            with open(CONFIG_FILE_PATH) as f:
                config = yaml.safe_load(f)

        # Initialize the helper
        helper = OpenCTIConnectorHelper(config)

        # Load all variables via config_variables.py
        vars = load_config_variables(helper, config)

        # Initialize the connector with the loaded variables
        connector = ZscalerConnector(
            config_path=CONFIG_FILE_PATH,
            helper=helper,
            opencti_url=vars["opencti_url"],
            opencti_token=vars["opencti_token"],
            ssl_verify=vars["ssl_verify"],
            zscaler_username=vars["zscaler_username"],
            zscaler_password=vars["zscaler_password"],
            zscaler_api_key=vars["zscaler_api_key"],
            zscaler_blacklist_name=vars["zscaler_blacklist_name"],
        )

        connector.authenticate_with_zscaler()
        connector.start()

    except Exception:
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)
