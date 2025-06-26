import time

from pycti import OpenCTIConnectorHelper

from api.doppel_api import fetch_alerts
from openCTI.client import send_to_opencti
from openCTI.stix_converter import convert_alert_to_bundle
from utils.config_helper import load_config, load_connector_config
from utils.constants import DOPPEL_ALERTS_ENDPOINT, DOPPEL_API_BASE_URL
from utils.state_handler import get_last_run, set_last_run

# Load configuration
config = load_config()
helper = OpenCTIConnectorHelper(config)
connector_config = load_connector_config(config, helper)

API_KEY = connector_config["API_KEY"]
POLLING_INTERVAL = connector_config["POLLING_INTERVAL"]
MAX_RETRIES = connector_config["MAX_RETRIES"]
RETRY_DELAY = connector_config["RETRY_DELAY"]
HISTORICAL_POLLING_DAYS = connector_config["HISTORICAL_POLLING_DAYS"]
UPDATE_EXISTING_DATA = connector_config["UPDATE_EXISTING_DATA"]

if __name__ == "__main__":
    helper.log_info("Starting Doppel OpenCTI connector...")

    while True:
        try:
            helper.log_info("Starting data fetch cycle...")

            # Get last run timestamp
            last_activity_timestamp = get_last_run(helper, HISTORICAL_POLLING_DAYS)

            API_URL = DOPPEL_API_BASE_URL + DOPPEL_ALERTS_ENDPOINT
            alerts = fetch_alerts(
                helper,
                API_URL,
                API_KEY,
                last_activity_timestamp,
                MAX_RETRIES,
                RETRY_DELAY,
            )
            helper.log_info(f"Fetched {len(alerts)} alerts from Doppel")

            if alerts:
                stix_bundle = convert_alert_to_bundle(alerts, helper)

                if stix_bundle:
                    send_to_opencti(stix_bundle, helper, UPDATE_EXISTING_DATA)
                else:
                    helper.log_info("No valid alerts to send.")

            # Save current timestamp as last run
            set_last_run(helper)

        except Exception as e:
            helper.log_error(f"Unexpected error in main loop: {str(e)}")

        helper.log_info(f"Sleeping for {POLLING_INTERVAL} seconds before next run...")
        time.sleep(POLLING_INTERVAL)
