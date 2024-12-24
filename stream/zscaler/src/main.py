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
        # Charger la config YAML
        config = {}
        if os.path.isfile(CONFIG_FILE_PATH):
            with open(CONFIG_FILE_PATH) as f:
                config = yaml.safe_load(f)

        # Initialiser le helper
        helper = OpenCTIConnectorHelper(config)

        # Charger toutes les variables via config_variables.py
        vars = load_config_variables(helper, config)

        # Initialiser le connecteur avec les variables chargées
        connector = ZscalerConnector(
            config_path=CONFIG_FILE_PATH,
            helper=helper,
            opencti_url=vars["opencti_url"],
            opencti_token=vars["opencti_token"],
            ssl_verify=vars["ssl_verify"],
            zscaler_username=vars["zscaler_username"],
            zscaler_password=vars["zscaler_password"],
            zscaler_api_key=vars["zscaler_api_key"],
        )

        connector.authenticate_with_zscaler()
        connector.start()

    except:
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)
